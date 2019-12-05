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
    for proj in os.listdir(core_path):
        proj = angr.Project(os.path.join(core_path, proj))
        proj.analyses.CFGFast()
        funcs = get_functions(proj)
        pickle.dump(funcs, open(f"dumps/{proj}.pkl", "wb"))
        analysis = dict()
        for fun in funcs:
            analysis[fun.name] = analyze_func(proj, fun)
        pickle.dump(analysis, open(f"dumps/{proj}_analysis.pkl", "wb"))


if __name__ == "__main__":
    main()

    # move binaries
    #  ls -al  | grep ^-rwxr | awk '{print $(NF)}' | while read line;do mv $line ~/my_binaries/;done
    # 