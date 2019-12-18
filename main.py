import angr
import os
import pickle


def is_qualified(symbol):
    avoid = set(['main', 'usage'])
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
    return sm.stashes


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


if __name__ == "__main__":
    # main()
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