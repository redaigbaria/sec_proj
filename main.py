from typing import Dict, Any

import angr
import os
import pickle
import re

bases_dict = dict()
replacement_dict = dict()

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
    if expr.depth > 2:
        raise Exception("should consider a new approach, your assumption is wrong!!")
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
        # depth is 2 (either a new sym-var is being declared or offset calc)
        if expr.op != "__add__":
            raise Exception("AAAAAA!!!")
        childs = list(expr.args)
        assert len(childs) < 3
        if len(childs) == 1:
            if state.solver.eval(expr) in bases_dict:
                return
            # new var is declared
            var_name = f"var_{len(bases_dict)}"
            bases_dict[state.inspect.address_concretization_result[0]] = var_name
            replacement_dict[state.inspect.address_concretization_result[0]] = f"{var_name}(0)"
        else:
            base = None
            offset = None
            for c in childs:
                if not c.concrete:
                    base = state.solver.eval(c)
                else:
                    offset = state.solver.eval(c)
            replacement_dict[state.inspect.address_concretization_result[0]] = f"{bases_dict[base]}({offset})"

def is_qualified(symbol):
    avoid = {'main', 'usage'}
    return symbol.is_function and symbol.is_export and not (symbol.name.startswith("_") or symbol.name in avoid)


def get_functions(proj):
    funcs = []
    for symb in proj.loader.main_object.symbols:
        if is_qualified(symb):
            funcs.append(symb)
    return funcs


def analyze_func(proj, fun, cfg):
    print(f"started running {fun.name}")
    call_state = proj.factory.call_state(fun.rebased_addr)
    call_state.inspect.b('address_concretization', when=angr.BP_AFTER, action=address_breakfun)
    sm = proj.factory.simulation_manager(call_state)
    sm.use_technique(angr.exploration_techniques.LoopSeer(cfg=cfg, bound=2))
    sm.run()
    print(f"finished {fun.name}")
    return sm.deadended


def main():
    core_path = "/home/reda/my_binaries"
    for proj_name in os.listdir(core_path):
        if os.path.exists(f"dumps/{proj_name}_functions.pkl"):
            continue
        print(f"analysing proj: {proj_name}")
        proj_path = os.path.join(core_path, proj_name)
        try:
            proj = angr.Project(proj_path)
        except Exception as e:
            print(f"{proj_name} loading failed")
            print(e)
            continue
        # proj.analyses.CFGFast()
        funcs = get_functions(proj)
        pickle.dump(funcs, open(f"dumps/{proj_name}_functions.pkl", "wb"))
        # analysis = dict()
        # for fun in funcs:
        #     analysis[fun.name] = analyze_func(proj, fun)
        # pickle.dump(analysis, open(f"dumps/{proj}_analysis.pkl", "wb"))


def block_to_ins(block: angr.block.Block):
    result = []
    for ins in block.capstone.insns:
        op_str = ins.op_str
        operands = op_str.strip(" ").split(",")
        operands = [i.strip().replace("[","").replace("]", "") for i in operands if i != ""]
        operands += ['', '']
        result.append(f"{ins.mnemonic}|{operands[0]}|{operands[1]}".replace(" ", "|"))
    return "|".join(result)


def cons_to_triple(constraint):
    if constraint.concrete:
        return ""
    if len(constraint.args) == 1:
        return f'{constraint.op}|{cons_to_triple(constraint.args[0])}'
    arg1 = f'{constraint.args[0]}'
    arg2 = f'{constraint.args[1]}'
    return f'{constraint.op}|{arg1.replace(" ", "|")}|{arg2.replace(" ", "|")}'


def relify(conts):
    for k, v in replacement_dict.items():
        conts = re.sub(f"(0x|mem_){format(k, 'x')}[_0-9]*", v, conts)
    return conts.replace('{UNINITIALIZED}', '')


def train_input():
    proj = angr.Project("test_binary", auto_load_libs=False)
    cfg = proj.analyses.CFGFast()
    funcs = get_functions(proj)
    output = open("generated_input2.txt", "w")
    for test_func in funcs:
        bases_dict.clear()
        replacement_dict.clear()
        constraints = analyze_func(proj, test_func, cfg)
        for constraint in constraints:
            blocks = [proj.factory.block(baddr) for baddr in constraint.history.bbl_addrs]
            processsed_code = "|".join(list(map(block_to_ins, blocks)))
            processed_consts = "|".join(list(map(cons_to_triple, constraint.solver.constraints)))
            relified_consts = relify(processed_consts)
            output.write(f"{test_func.name} DUM,{processsed_code}|CONS|{relified_consts},DUM\n")


if __name__ == "__main__":
    # main()
    train_input()
    exit()
    hist = dict()
    p = "dumps"
    for name in os.listdir(p):
        funcs = pickle.load(open(f"dumps/{name}", "rb"))
        for f in funcs:
            hist[f.name] = hist.get(f.name, 0) +  1
    b = list(hist.items())
    b.sort(key=lambda x: x[1], reverse=True)
    print(b)
    c = 0
    for k, v in b:
        c += v

    print(c)
    # move binaries
    #  ls -al  | grep ^-rwxr | awk '{print $(NF)}' | while read line;do mv $line ~/my_binaries/;done
    # 