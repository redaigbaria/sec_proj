from typing import Dict, Any

import angr
import os
import pickle
import re
import shutil
import time
import logging
import json
import argparse
import itertools
from glob import glob

bases_dict = dict()
replacement_dict = dict()
start_time = 0

def address_breakfun(state):
    exit(1)
    # if not state.inspect.address_concretization_add_constraints:
    #     return
    if state.inspect.address_concretization_result is None:
        return

    # if len(state.inspect.address_concretization_expr.args) == 1:
    #     bases.add()
    # print(state.inspect.address_concretization_expr.op)
    # print(f"{hex(state.inspect.address_concretization_result[0])}")
    # print(f"{state.inspect.address_concretization_expr}")
    expr = state.inspect.address_concretization_expr
    # if expr.depth > 2:
    #     raise Exception("should consider a new approach, your assumption is wrong!!")
    if expr.depth == 1:
        if expr.op != "BVS":
            raise Exception("AAAAAA!!!")
        if state.solver.eval(expr) in bases_dict:
            return
        # new var is declared
        var_name = f"var_{len(bases_dict)}"
        bases_dict[state.inspect.address_concretization_result[0]] = var_name
        replacement_dict[state.inspect.address_concretization_result[0]] = f"{var_name}(0)"
    else:
        # depth is 2 (either a new symbolic-var is being declared or offset calc)
        if expr.op != "__add__":
            print(f"found new op: {expr.op}")
            return
        children = list(expr.args)
        # assert len(children) < 3
        if len(children) > 2:
            print("warning, an expression with more than 2 children is being relativised")
        if len(children) == 1:
            if state.solver.eval(expr) in bases_dict:
                return
            # new var is declared
            var_name = f"var_{len(bases_dict)}"
            bases_dict[state.inspect.address_concretization_result[0]] = var_name
            replacement_dict[state.inspect.address_concretization_result[0]] = f"{var_name}(0)"
        else:
            base = None
            offset = None
            for c in children:
                if not c.concrete:
                    base = state.solver.eval(c)
                else:
                    offset = state.solver.eval(c)
            if base not in bases_dict:
                return
            replacement_dict[state.inspect.address_concretization_result[0]] = f"{bases_dict[base]}({offset})"


def time_limit_check(smgr):
    global start_time
    minutes_limit = 1
    should_stop = time.time() - start_time > (60 * minutes_limit)
    if should_stop:
        print("stopped exploration")
    return should_stop


def analyze_func(proj, fun, cfg):
    print(f"started running {fun.name}")
    call_state = proj.factory.call_state(fun.addr, add_options={
        'CALLLESS': True, 'NO_SYMBOLIC_SYSCALL_RESOLUTION': True
    })
    # call_state.inspect.b('address_concretization', when=angr.BP_AFTER, action=address_breakfun)
    sm = proj.factory.simulation_manager(call_state)
    sm.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg, bound=2))
    global start_time
    start_time = time.time()
    sm.run(until=time_limit_check)
    print(f"finished {fun.name}")
    return sm


def get_cfg_funcs(proj, binary, excluded):
    return list(filter(None, [f if f.binary_name == binary and (not f.is_plt) and not f.name.startswith(
        "sub_") and not f.name.startswith("_") and f.name not in excluded and f.symbol.is_export else None for f in
                              proj.kb.functions.values()]))


def block_to_ins(block: angr.block.Block):
    result = []
    for ins in block.capstone.insns:
        op_str = ins.op_str
        operands = op_str.strip(" ").split(",")
        operands = [i.strip().replace("[","").replace("]", "") for i in operands if i != ""]
        parsed_ins = [ins.mnemonic] + list(filter(None, operands))
        result.append("|".join(parsed_ins).replace(" ", "|") + "|\t")
        # result.append(f"{ins.mnemonic}|{operands[0]}|{operands[1]}".replace(" ", "|"))
    return "|".join(result)


def cons_to_triple(constraint):
    if constraint.concrete:
        return ""
    # if len(constraint.args) == 1:
    #     return f'{constraint.op}|{cons_to_triple(constraint.args[0])}'
    # arg1 = f'{constraint.args[0]}'
    # arg2 = f'{constraint.args[1]}'
    args = list(filter(None, map(str, constraint.args)))
    triple = [constraint.op] + args
    return "|".join(triple).replace(" ", "|") + "\t"
    # return f'{constraint.op}|{arg1.replace(" ", "|")}|{arg2.replace(" ", "|")}'


def relify(constraints):
    for k, v in replacement_dict.items():
        constraints = re.sub(f"(0x|mem_){format(k, 'x')}[_0-9]*", v, constraints)
    return constraints.replace('{UNINITIALIZED}', '')


def remove_consecutive_pipes(s1):
    return re.sub("(\|)+", "|", s1)


def con_to_str(con, replace_strs=[', ', ' ', '(', ')'], max_depth=8):
    repr = con.shallow_repr(max_depth=max_depth, details=con.MID_REPR).replace('{UNINITIALIZED}', '')
    for r_str in replace_strs:
        repr = repr.replace(r_str, '|')

    return remove_consecutive_pipes(repr) + "\t"


def gen_new_name(old_name, counters):
    if re.match(r"mem", old_name):
        return 'mem_%d' % next(counters['mem'])
    if re.match(r"fake_ret_value", old_name):
        return 'ret_%d' % next(counters['ret'])
    if re.match(r"reg", old_name):
        return re.sub("(_[0-9]+)+", '', old_name)
    if re.match(r"unconstrained_ret", old_name):
        return re.sub("(_[0-9]+)+", '', old_name[len("unconstrained_ret_") : ])
    return old_name


def varify_cons(cons , var_map=None, counters=None, max_depth=8):
    counters = {'mem': itertools.count(), 'ret': itertools.count()} if counters is None else counters
    var_map = {} if var_map is None else var_map
    new_cons = []

    for con in cons:
        if con.concrete:
            continue
        for v in con.leaf_asts():
            if v.cache_key not in var_map and v.op in { 'BVS', 'BoolS', 'FPS' }:
                new_name = gen_new_name(v.args[0], counters=counters)
                var_map[v.cache_key] = v._rename(new_name)
        new_cons.append(con_to_str(con.replace_dict(var_map), max_depth=max_depth))

    return var_map, new_cons


def tokenize_function_name(function_name):
    return "|".join(function_name.split("_"))


def generate_dataset(train_binaries, dataset_name):
    dataset_dir = f"datasets/{dataset_name}"
    os.makedirs(dataset_dir, exist_ok=True)
    analysed_funcs = get_analysed_funcs(dataset_dir)
    for binary in train_binaries:
        analysed_funcs = analyse_binary(analysed_funcs, binary, dataset_dir)


def analyse_binary(analysed_funcs, binary_name, dataset_dir):
    excluded = {'main', 'usage', 'exit'}.union(analysed_funcs)
    proj = angr.Project(binary_name, auto_load_libs=False)
    cfg = proj.analyses.CFGFast()
    # cfg = proj.analyses.CFGEmulated()
    binary_name = os.path.basename(binary_name)
    binary_dir = os.path.join(dataset_dir, f"{binary_name}")
    os.makedirs(binary_dir, exist_ok=True)
    funcs = get_cfg_funcs(proj, binary_name, excluded)
    output = open(f"{binary_dir}/output.txt", "a")
    print(f"{binary_name} have {len(funcs)} funcs")
    for test_func in funcs:
        if test_func.name in analysed_funcs:
            print(f"skipping {test_func.name}")
            continue
        print(f"analyzing {binary_name}/{test_func.name}")
        # bases_dict.clear()
        # replacement_dict.clear()
        analysed_funcs.add(test_func.name)
        try:
            sm: angr.sim_manager.SimulationManager = analyze_func(proj, test_func, cfg)
            sm_file = open(os.path.join(binary_dir, f"{test_func.name}.pkl"), "wb")
            pickle.dump(sm, sm_file)
            sm_file.close()
            # exec_paths = sm.deadended
            # if len(exec_paths) == 0:
            #     processsed_code = "|".join(list(filter(None, map(block_to_ins, test_func.blocks))))
            #     output.write(
            #         f"{tokenize_function_name(test_func.name)} DUM,{processsed_code}|CONS|NONE,DUM\n")
            # else:
            #     counters = {'mem': itertools.count(), 'ret': itertools.count()}
            #     var_map = {}
            #     for exec_path in exec_paths:
            #         blocks = [proj.factory.block(baddr) for baddr in exec_path.history.bbl_addrs]
            #         processsed_code = "|".join(list(filter(None, map(block_to_ins, blocks))))
            #         var_map, relified_consts = varify_cons(exec_path.solver.constraints, var_map=var_map, counters=counters)
            #         relified_consts = "|".join(relified_consts)
            #         #processed_consts = "|".join(list(filter(None, map(cons_to_triple, exec_path.solver.constraints))))
            #         #relified_consts = relify(processed_consts)
            #         output.write(
            #             f"{tokenize_function_name(test_func.name)} DUM,{processsed_code}|CONS|{relified_consts},DUM\n")
        except Exception as e:
            logging.error(str(e))
            logging.error(f"got an error while analyzing {test_func.name}")
    output.close()
    return analysed_funcs


def get_functions_histogram():
    """
        in order to exclude coreutils-library functions from analysis
    """
    binaries = os.listdir("coreutils_bins")
    binaries.sort()
    binaries = [f"coreutils_bins/{binary}" for binary in binaries][50:70]
    hist = dict()
    for binary in binaries:
        proj = angr.Project(binary, auto_load_libs=False)
        proj.analyses.CFGFast()
        binary = os.path.basename(binary)
        funcs = get_cfg_funcs(proj, binary, {'main', 'usage', 'exit'})
        for func in funcs:
            hist[func.name] = hist.get(func.name, 0) + 1

    json.dump(hist, open("functions_histogram.json", "w"))
    b = list(hist.items())
    b.sort(key=lambda x: x[1], reverse=True)
    print(b)

    #
    # def canonicalize(self, var_map=None, counter=None):
    #     counter = itertools.count() if counter is None else counter
    #     var_map = { } if var_map is None else var_map
    #
    #     for v in self.leaf_asts():
    #         if v.cache_key not in var_map and v.op in { 'BVS', 'BoolS', 'FPS' }:
    #             new_name = 'canonical_%d' % next(counter)
    #             var_map[v.cache_key] = v._rename(new_name)
    #
    #     return var_map, counter, self.replace_dict(var_map)
    #
    # #


def remove_failed_pkls(dataset_path):
    binaries = os.scandir(dataset_path)
    failed_funcs = []
    for entry in binaries:
        funcs = glob(f"{entry.path}/*.pkl")
        for func in funcs:
            with open(func, "rb") as f:
                try:
                    sm = pickle.load(f)
                    print(f"{func} have {sm}")
                except:
                    print(f"{func} failed")
                    failed_funcs.append(func)

    # for failed_func in failed_funcs:
    #     os.remove(failed_func)
    print(set(failed_funcs))


def get_analysed_funcs(dataset_path):
    binaries = os.scandir(dataset_path)
    analysed_funcs = set()
    for entry in binaries:
        funcs = glob(f"{entry.path}/*.pkl")
        analysed_funcs.update(map(lambda x: x[:-len(".pkl")], map(os.path.basename, funcs)))

    return analysed_funcs


def sm_to_output(sm: angr.sim_manager.SimulationManager, output_file, func_name):
    counters = {'mem': itertools.count(), 'ret': itertools.count()}
    var_map = {}
    skipped_lines = 0
    proj = sm._project
    for exec_paths in sm.stashes.values():
        for exec_path in exec_paths:
            blocks = [proj.factory.block(baddr) for baddr in exec_path.history.bbl_addrs]
            processsed_code = "|".join(list(filter(None, map(block_to_ins, blocks))))
            var_map, relified_consts = varify_cons(exec_path.solver.constraints, var_map=var_map, counters=counters)
            relified_consts = "|".join(relified_consts)
            line = f"{tokenize_function_name(func_name)} DUM,{processsed_code}|CONS|{relified_consts},DUM\n"
            if len(line) <= 3000:
                output_file.write(line)
            else:
                skipped_lines += 1
    print(f"skipped {skipped_lines} lines")


def generate_output(dataset_path):
    binaries = list(os.scandir(dataset_path))
    import numpy as np
    np.random.seed(42)
    np.random.shuffle(binaries)
    train_output = open(os.path.join(dataset_path, "train_output.txt"), "w")
    test_output = open(os.path.join(dataset_path, "test_output.txt"), "w")
    val_output = open(os.path.join(dataset_path, "val_output.txt"), "w")
    analysed_funcs = set()
    output = train_output
    for i, entry in enumerate(binaries):
        if i == 50:
            output = val_output
        if i == 60:
            output = test_output
        funcs = glob(f"{entry.path}/*.pkl")
        for func in funcs:
            if os.path.basename(func) in analysed_funcs:
                continue
            with open(func, "rb") as f:
                try:
                    func_name = os.path.basename(func)
                    func_name = func_name[:-len(".pkl")]
                    analysed_funcs.add(os.path.basename(func))
                    sm = pickle.load(f)
                    sm_to_output(sm, output, func_name)
                except Exception as e:
                    print(e)
                    print(f"{func} failed")
                    # failed_funcs.append(func)
    train_output.close()
    test_output.close()
    val_output.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary_idx", type=int, required=True)
    args = parser.parse_args()
    binaries = os.listdir("coreutils_bins")
    binaries.sort()
    binaries = [f"coreutils_bins/{binary}" for binary in binaries]
    generate_dataset([binaries[args.binary_idx]], "cfg_overfitting_test")
    print("successfully exited")


def trim_long_lines(file_path):
    file = open(file_path, "r")
    output_path = os.path.join(os.path.dirname(file_path), f"trimmed_{os.path.basename(file_path)}")
    output_file = open(output_path, "w")
    max_100_lengths = [0] * 100
    counter = 0
    lengths = []

    for line in file:
        curr_min = min(max_100_lengths)
        lengths.append(len(line))
        if len(line) > 2500:
            counter += 1
        else:
            output_file.write(line)
        if len(line) > curr_min:
            max_100_lengths[max_100_lengths.index(curr_min)] = len(line)
    max_100_lengths.sort(reverse=True)
    print(max_100_lengths)
    print(counter)
    import matplotlib.pyplot as plt
    plt.hist(lengths, bins='auto')
    plt.show()


if __name__ == '__main__':
    # cut long lines
    # trim_long_lines("datasets/cfg_overfitting_test/collective_output.txt")
    generate_output("datasets/cfg_overfitting_test")

    exit()
    main()
    # A test to detremine wether to use CFGFast or EmulatedCFG for finding functions in the binary... it turns out
    # should use CFGFast, but remove all undefined symbols that it adds (starts with sub_xxx)
    # binaries = ['core_utils_bins/ls']
    # for bin in binaries:
    #     proj = angr.Project(bin, auto_load_libs=False)
    #     # efg = proj.analyses.CFGEmulated()
    #     cfg = proj.analyses.CFGFast()
    #     cfg_functions = {f.name for f in cfg.kb.functions.values()}
    #     # efg_functions = {f.name for f in efg.kb.functions.values()}
    #
    #     # with open(f"jsons/{os.path.basename(bin)}.json", "w") as f:
    #     #     json.dump({"cfg": list(cfg_functions), "efg": list(efg_functions),
    #     #                "diff": list(cfg_functions.symmetric_difference(efg_functions))},
    #     #               f, indent=4)
    #     # pickle.dump(efg_functions, open("emulated_ls_test.pkl", "wb"))
    #     pickle.dump(cfg_functions, open("cfg_ls_test.pkl", "wb"))
    #     print(f"finished {bin}")
    # exit()
    # generate_dataset(binaries[0:20], dataset_name="overfitting_test")
    # exit()
    # hist = dict()
    # p = "dumps"
    # for name in os.listdir(p):
    #     funcs = pickle.load(open(f"dumps/{name}", "rb"))
    #     for f in funcs:
    #         hist[f.name] = hist.get(f.name, 0) + 1
    # b = list(hist.items())
    # b.sort(key=lambda x: x[1], reverse=True)
    # print(b)
    # c = 0
    # for k, v in b:
    #     c += v
    #
    # print(c)
    # move binaries
    #  ls -al  | grep ^-rwxr | awk '{print $(NF)}' | while read line;do cp $line ~/sec_proj/coreutils_bins;done
    #