from typing import Dict, Any

import angr
import os
import pickle
import re
import shutil
import time
import logging
import json


bases_dict = dict()
replacement_dict = dict()

start_time = 0

def address_breakfun(state):
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

def is_qualified(symbol):
    avoid = {'main', 'usage', 'exit'}
    return symbol.is_function and symbol.is_export and not (symbol.name.startswith("_") or symbol.name in avoid)


def get_functions(proj):
    funcs = []
    for symb in proj.loader.main_object.symbols:
        if is_qualified(symb):
            funcs.append(symb)
    return funcs


def get_cfg_functions(proj):
    funcs = []
    for f in proj.kb.functions.values():


def time_limit_check():
    global start_time
    minutes_limit = 1
    should_stop = time.time() - start_time > (60 * minutes_limit)
    if should_stop:
        print("stopped exploration")
    return should_stop


def analyze_func(proj, fun, cfg):
    print(f"started running {fun.name}")
    call_state = proj.factory.call_state(fun.rebased_addr, add_options={
        'CALLLESS': True, 'NO_SYMBOLIC_SYSCALL_RESOLUTION': True
    })
    call_state.inspect.b('address_concretization', when=angr.BP_AFTER, action=address_breakfun)
    sm = proj.factory.simulation_manager(call_state)
    sm.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg, bound=2))
    global start_time
    start_time = time.time()
    sm.run(until=time_limit_check)
    print(f"finished {fun.name}")
    return sm.deadended


def save_functions_names():
    core_path = "coreutils_bins"
    for proj_name in os.listdir(core_path):
        if os.path.exists(f"dumps/{proj_name}_functions.pkl"):
            continue
        print(f"analysing proj: {proj_name}")
        proj_path = os.path.join(core_path, proj_name)
        try:
            proj = angr.Project(proj_path, auto_load_libs=False)
        except Exception as e:
            logging.error(f"{proj_name} loading failed")
            print(e)
            continue
        funcs = get_functions(proj)
        pickle.dump(funcs, open(f"dumps/{proj_name}_functions.pkl", "wb"))


def block_to_ins(block: angr.block.Block):
    result = []
    for ins in block.capstone.insns:
        op_str = ins.op_str
        operands = op_str.strip(" ").split(",")
        operands = [i.strip().replace("[","").replace("]", "") for i in operands if i != ""]
        parsed_ins = [ins.mnemonic] + list(filter(None, operands))
        result.append("|".join(parsed_ins).replace(" ", "|") + "\t")
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


def tokenize_function_name(function_name):
    return "|".join(function_name.split("_"))


def generate_dataset(train_binaries, dataset_name):
    output_name = f"datasets/{dataset_name}.txt"
    output = open(output_name, "w")
    analysed_funcs = set()
    for binary in train_binaries:
        proj = angr.Project(binary, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()
        # funcs = get_functions(proj)

        for test_func in proj.kb.functions.values():
            if test_func.name in analysed_funcs:
                print(f"skipping {test_func.name}")
                continue
            print(f"analyzing {binary}/{test_func.name}")
            bases_dict.clear()
            replacement_dict.clear()
            try:
                exec_paths = analyze_func(proj, test_func, cfg)
                if len(exec_paths) == 0:
                    continue
                for exec_path in exec_paths:
                    blocks = [proj.factory.block(baddr) for baddr in exec_path.history.bbl_addrs]
                    processsed_code = "|".join(list(filter(None, map(block_to_ins, blocks))))
                    processed_consts = "|".join(list(filter(None, map(cons_to_triple, exec_path.solver.constraints))))
                    relified_consts = relify(processed_consts)
                    output.write(f"{tokenize_function_name(test_func.name)} DUM,{processsed_code}|CONS|{relified_consts},DUM\n")
            except Exception as e:
                logging.error(str(e))
                logging.error(f"got an error while analyzing {test_func.name}")
            analysed_funcs.add(test_func.name)
    output.close()
    # shutil.copy2(output_name, f"code2seq/{dataset_name}.train.raw.txt")
    # shutil.copy2(output_name, f"code2seq/{dataset_name}.val.raw.txt")
    # shutil.copy2(output_name, f"code2seq/{dataset_name}.test.raw.txt")
    # os.remove(output_name)




if __name__ == "__main__":
    # note: some functions are shared among most of the binaries,
    # should consider removing them from the learning scheme, or adding them just once in the dataset
    binaries = os.listdir("coreutils_bins")
    binaries.sort()
    binaries = [f"coreutils_bins/{binary}" for binary in binaries]
    # mv
    generate_dataset(binaries[51:52], "new_test")
    exit()
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
    hist = dict()
    p = "dumps"
    for name in os.listdir(p):
        funcs = pickle.load(open(f"dumps/{name}", "rb"))
        for f in funcs:
            hist[f.name] = hist.get(f.name, 0) + 1
    b = list(hist.items())
    b.sort(key=lambda x: x[1], reverse=True)
    print(b)
    c = 0
    for k, v in b:
        c += v

    print(c)
    # move binaries
    #  ls -al  | grep ^-rwxr | awk '{print $(NF)}' | while read line;do cp $line ~/sec_proj/coreutils_bins;done
    # 