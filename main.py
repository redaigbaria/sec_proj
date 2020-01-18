import angr
import os
import pickle


def is_qualified(symbol):
    avoid = {'main', 'usage'}
    return symbol.is_function and symbol.is_export and not (symbol.name.startswith("_") or symbol.name in avoid)


def get_functions(proj):
    funcs = []
    for symb in proj.loader.main_object.symbols:
        if is_qualified(symb):
            funcs.append(symb)
    return funcs


def analyze_func(proj, fun):
    print(f"started running {fun.name}")
    call_state = proj.factory.call_state(fun.rebased_addr)
    sm = proj.factory.simulation_manager(call_state)
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
        operands += ['UNK', 'UNK']
        result.append(f"{ins.mnemonic},{operands[0]},{operands[1]}".replace(" ", "|"))
    return " ".join(result)


def train_input():
    proj = angr.Project("test_binary")
    proj.analyses.CFGFast()
    funcs = get_functions(proj)
    output = open("generated_input.txt", "w")
    for test_func in funcs:
        constraints = analyze_func(proj, test_func)
        for constraint in constraints:
            blocks = [proj.factory.block(baddr) for baddr in constraint.history.bbl_addrs]
            processsed_code = " ".join(list(map(block_to_ins, blocks)))
            output.write(f"{test_func.name} {processsed_code} CONS,CONS,CONS\n")


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
    for k,v in b:
        c += v

    print(c)
    # move binaries
    #  ls -al  | grep ^-rwxr | awk '{print $(NF)}' | while read line;do mv $line ~/my_binaries/;done
    # 