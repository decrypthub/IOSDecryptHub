"""检查不支持的 ObjC post 采集在安装前拒绝，且 Hook 列表不变。

显式指定已授权设备及浮点/聚合 ABI 的方法。不调用目标方法。
固定 GPR 栈参数已受支持，不能用来充当拒绝案例。
python tests/method_hook_guard_test.py --endpoint http://<device>:8088 --class-name <class> --selector <selector>
"""
import argparse
import json
from urllib.request import Request, urlopen


def call(endpoint, name, arguments):
    body = json.dumps({"jsonrpc": "2.0", "id": name, "method": "tools/call",
                       "params": {"name": name, "arguments": arguments}}).encode()
    request = Request(endpoint.rstrip("/") + "/api/mcp", body,
                      {"Content-Type": "application/json"})
    with urlopen(request, timeout=15) as response:
        return json.load(response)["result"]


def check(endpoint, class_name, selector, class_method=False):
    cap = call(endpoint, "get_capabilities", {})
    cap = cap.get("structuredContent") or json.loads(cap["content"][0]["text"])
    generation = cap["processGeneration"]
    before = call(endpoint, "list_hooks", {})
    for options in ({"capture_return": True},
                    {"capture_after": True, "capture_memory": {"ptr_arg": 2, "max_bytes": 8}},
                    {"capture_ret_multi": "x0:8"}):
        result = call(endpoint, "hook_method", {"class": class_name, "selector": selector,
                      "classMethod": class_method, "process_generation": generation,
                      "post_abi": "fixed-nonvariadic", **options})
        assert result.get("isError"), result
        text = " ".join(x.get("text", "") for x in result.get("content", []))
        assert "post" in text and "ABI" in text, text
        # hits 会自然变化；只比较槽位/配置，不要求业务线程停止。
        def stable(value):
            payload = value.get("structuredContent")
            if payload is None:
                payload = json.loads(value["content"][0]["text"])
            def clean(item):
                if isinstance(item, dict):
                    return {k: clean(v) for k, v in item.items() if k not in {"hits", "inFlight"}}
                if isinstance(item, list):
                    return [clean(v) for v in item]
                return item
            return clean(payload)
        assert stable(call(endpoint, "list_hooks", {})) == stable(before)
    print("PASS: 3 unsupported post requests rejected without changing hooks")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True)
    parser.add_argument("--class-name", required=True)
    parser.add_argument("--selector", required=True)
    parser.add_argument("--class-method", action="store_true")
    args = parser.parse_args()
    check(args.endpoint, args.class_name, args.selector, args.class_method)
