#!/usr/bin/env python3
"""Runs tests/itest/test_*.py: every top-level function named test_* is one test.
usage: tests/itest/run.py [substring-filter ...]   (exit status 1 if any test fails)"""
import glob, importlib.util, os, sys, time, traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)


def main():
    filters = sys.argv[1:]
    passed, failed = 0, []
    for path in sorted(glob.glob(os.path.join(HERE, "test_*.py"))):
        mod_name = os.path.basename(path)[:-3]
        spec = importlib.util.spec_from_file_location(mod_name, path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        for name in sorted(n for n in dir(mod) if n.startswith("test_")):
            full = f"{mod_name}.{name}"
            if filters and not any(f in full for f in filters):
                continue
            t0 = time.time()
            try:
                getattr(mod, name)()
                passed += 1
                print(f"  ok    {full} ({time.time() - t0:.1f}s)", flush=True)
            except Exception:
                failed.append(full)
                print(f"  FAIL  {full}\n" + "".join("      " + l for l in traceback.format_exc().splitlines(True)), flush=True)
    print(f"\n{passed} passed, {len(failed)} failed")
    for f in failed:
        print("  FAILED:", f)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
