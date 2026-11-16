"""Keep the frontend handoff consistent with actual routes and runnable examples."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
DOCUMENT = ROOT / "net-assistant/backend/docs/前端对接说明.md"
CONTRACT = ROOT / "net-assistant/backend/docs/openapi-0.10.0.json"
HTTP_METHODS = {"get", "post", "put", "patch", "delete", "head", "options"}


class FrontendHandoffTests(unittest.TestCase):
    def test_links_and_current_collaborator_baseline(self):
        text = DOCUMENT.read_text("utf-8")
        self.assertIn("## 0. 前端先读：最短联调路径", text)
        self.assertIn("http://127.0.0.1:8001", text)
        self.assertIn("changeOrigin", text)
        self.assertIn("48", text)
        self.assertNotRegex(text, r"(?<![A-Za-z])[A-Za-z]:(?:\\|/(?!/))")
        self.assertNotIn("当前本机地址 | `http://127.0.0.1:8000`", text)
        self.assertNotIn("尚未正式启用", text)
        self.assertEqual(text.count("```") % 2, 0)
        for link in re.findall(r"\[[^\]]+\]\(([^)]+)\)", text):
            if not link.startswith(("https://", "http://", "#")):
                self.assertTrue((DOCUMENT.parent / link.split("#", 1)[0]).is_file(), link)
        for block in re.findall(r"```json\n(.*?)```", text, re.S):
            json.loads(block)

    def test_api_index_static_references_and_factory_routes_agree(self):
        schema = json.loads(CONTRACT.read_text("utf-8"))
        expected = {(method.upper(), path) for path, methods in schema["paths"].items()
                    for method in methods if method in HTTP_METHODS}
        text = DOCUMENT.read_text("utf-8")
        match = re.search(r"<!-- api-index:start -->(.*?)<!-- api-index:end -->", text, re.S)
        self.assertIsNotNone(match, "The complete method/path index must be explicit.")
        rows = re.findall(r"\|\s*(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s*"
                          r"\|\s*`([^`]+)`", match.group(1))
        self.assertEqual(len(rows), len(expected), "Each operation must occur exactly once.")
        self.assertEqual(set(rows), expected)

        def check_refs(value):
            if isinstance(value, dict):
                if "$ref" in value:
                    reference = value["$ref"]
                    self.assertTrue(reference.startswith("#/"))
                    target = schema
                    for part in reference[2:].split("/"):
                        target = target[part.replace("~1", "/").replace("~0", "~")]
                for item in value.values():
                    check_refs(item)
            elif isinstance(value, list):
                for item in value:
                    check_refs(item)
        check_refs(schema)
        with tempfile.TemporaryDirectory(prefix="frontend-contract-") as directory:
            database = Path(directory) / "must-not-be-created.sqlite"
            code = (
                "import json,sys;from pathlib import Path;"
                "sys.path.insert(0,sys.argv[1]);from app.main import create_app;"
                "schema=create_app(database_path=Path(sys.argv[2])).openapi();"
                "print(json.dumps({'version':schema['info']['version'],"
                "'routes':[(m.upper(),p) for p,v in schema['paths'].items() "
                "for m in v if m in " + repr(HTTP_METHODS) + "]}))"
            )
            result = subprocess.run(
                [sys.executable, "-c", code, str(ROOT / "net-assistant/backend"), str(database)],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, encoding="utf-8")
            self.assertEqual(result.returncode, 0, result.stderr)
            live = json.loads(result.stdout)
            self.assertEqual(live["version"], "0.10.0")
            self.assertEqual({tuple(item) for item in live["routes"]}, expected)
            self.assertFalse(database.exists())

    def test_typescript_examples_compile_and_mocked_fetch_scenarios(self):
        node = ROOT / ".runtime/tools/node/node.exe"
        if not node.is_file():
            executable = shutil.which("node")
            if not executable:
                self.skipTest("Node is required; run the documented environment setup.")
            node = Path(executable)
        compiler = ROOT / ".runtime/frontend/node_modules/typescript/lib/tsc.js"
        if not compiler.is_file():
            self.skipTest("The prepared frontend compiler is required; run setup.")
        blocks = re.findall(r"```ts\n(.*?)```", DOCUMENT.read_text("utf-8"), re.S)
        self.assertGreaterEqual(len(blocks), 11)
        with tempfile.TemporaryDirectory(prefix="frontend-examples-") as directory:
            temporary = Path(directory)
            examples = temporary / "examples.ts"
            examples.write_text("\n\n".join(blocks), encoding="utf-8")
            compiled = subprocess.run(
                [str(node), str(compiler), str(examples), "--strict", "--target", "ES2022",
                 "--module", "commonjs", "--lib", "ES2022,DOM", "--skipLibCheck",
                 "--outDir", str(temporary / "compiled")],
                cwd=temporary, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding="utf-8", errors="replace")
            self.assertEqual(compiled.returncode, 0, compiled.stdout)
            script = temporary / "scenarios.cjs"
            script.write_text(FETCH_SCENARIOS, encoding="utf-8")
            checked = subprocess.run([str(node), str(script)], cwd=temporary,
                                     stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                     text=True, encoding="utf-8", errors="replace",
                                     env=dict(os.environ, HTTP_PROXY="", HTTPS_PROXY="", ALL_PROXY=""))
            self.assertEqual(checked.returncode, 0, checked.stdout)
            self.assertIn("mocked_fetch_groups=13", checked.stdout)


FETCH_SCENARIOS = r"""
const assert = require("node:assert/strict");
const api = require("./compiled/examples.js");
const session = {user:{id:"fixture-user",username:"fixture",role:"admin"},
                 csrfToken:"fixture-csrf",expiresAt:"2026-11-16T12:00:00Z"};
let calls = [];
let queue = [];
function mock(...responses) {
  calls = []; queue = responses;
  global.fetch = async (url, init) => {
    calls.push({url,init});
    assert.ok(queue.length, "Unexpected request or automatic replay");
    const next = queue.shift();
    if (next instanceof Error) throw next;
    return new Response(JSON.stringify(next.body), {
      status:next.status ?? 200, headers:{"Content-Type":"application/json","X-Request-ID":"fixture-request"}
    });
  };
}
async function main() {
  let groups = 0;
  mock({body:session});
  await api.loginPlatform("fixture", "invented-client-fixture");
  assert.equal(calls[0].url,"/api/v1/auth/login");
  assert.equal(calls[0].init.credentials,"same-origin");
  assert.equal(calls[0].init.headers["X-CSRF-Token"],undefined);
  assert.equal(JSON.parse(calls[0].init.body).username,"fixture");
  groups++;

  mock({status:401,body:{code:"authentication_required",message:"Login required"}});
  assert.equal(await api.restorePlatformSession(),null);
  mock({status:503,body:{code:"access_store_unavailable",message:"Unavailable"}});
  await assert.rejects(api.restorePlatformSession(),e=>e instanceof api.ApiFailure && e.status===503);
  groups++;

  mock(new Error("fixture offline"));
  await assert.rejects(api.restorePlatformSession(),/fixture offline/);
  groups++;

  mock({body:{status:"logged_out"}});
  await api.logoutPlatform(session);
  assert.equal(calls[0].url,"/api/v1/auth/logout");
  assert.equal(calls[0].init.headers["X-CSRF-Token"],session.csrfToken);
  assert.deepEqual(JSON.parse(calls[0].init.body),{});
  groups++;

  mock({body:{status:"password_changed",reauthenticationRequired:true}});
  const changed=await api.changePlatformPassword(session,"old-fixture","new-fixture-password");
  assert.equal(changed.reauthenticationRequired,true);
  assert.deepEqual(JSON.parse(calls[0].init.body),
                   {currentPassword:"old-fixture",newPassword:"new-fixture-password"});
  groups++;

  const controller=new AbortController();
  mock({body:{items:[1],nextCursor:"20"}},{body:{items:[2],nextCursor:null}});
  assert.deepEqual(await api.readAll("/discovery-jobs/id/probes?address=192.0.2.10&method=tcp",
                                    controller.signal),[1,2]);
  const query=new URL(calls[1].url,"http://fixture.invalid").searchParams;
  assert.equal(query.get("address"),"192.0.2.10");
  assert.equal(query.get("method"),"tcp");
  assert.equal(query.get("cursor"),"20");
  assert.equal(calls[0].init.signal,controller.signal);
  groups++;

  mock({body:{items:[],nextCursor:"20"}},{body:{items:[],nextCursor:"20"}});
  await assert.rejects(api.readAll("/assets"),/重复分页游标/);
  assert.equal(calls.length,2);
  mock({body:{items:[],nextCursor:"20"}});
  await assert.rejects(api.readAll("/assets",undefined,1),/分页上限/);
  assert.equal(calls.length,1);
  groups++;

  mock({body:{id:"fixture-session",state:"ready"}});
  await api.openControlledTerminal(session,"fixture-target");
  assert.equal(calls.length,1);
  assert.equal(calls[0].url,"/api/v1/terminal/sessions");
  mock({body:{id:"fixture-operation",state:"prepared"}});
  await api.prepareControlledCommand(session,"fixture/session","fixture-command",{});
  assert.equal(calls.length,1);
  assert.equal(calls[0].url,"/api/v1/terminal/sessions/fixture%2Fsession/operations");
  groups++;

  const op={id:"fixture-operation",requiresDoubleConfirmation:true,state:"prepared"};
  mock();
  assert.throws(()=>api.executePreparedCommand(session,op),/缺少/);
  assert.equal(calls.length,0);
  const token={id:op.id,confirmationToken:"fixture-confirmation",expiresAt:session.expiresAt};
  mock({body:{...op,state:"completed"}});
  await api.executePreparedCommand(session,op,token);
  assert.equal(calls.length,1);
  assert.equal(calls[0].init.headers["X-CSRF-Token"],session.csrfToken);
  assert.deepEqual(JSON.parse(calls[0].init.body),{confirmationToken:token.confirmationToken});
  groups++;

  mock({body:{items:[{id:"42"}],nextCursor:null}});
  let batch=await api.readTerminalEventBatch("fixture-session","20");
  assert.equal(batch.cursor,"42");assert.equal(batch.hasMore,false);
  mock({body:{items:[],nextCursor:null}});
  batch=await api.readTerminalEventBatch("fixture-session","42");
  assert.equal(batch.cursor,"42");
  mock({body:{items:[{id:"43"}],nextCursor:"43"}});
  batch=await api.readTerminalEventBatch("fixture-session","42");
  assert.equal(batch.cursor,"43");assert.equal(batch.hasMore,true);
  groups++;

  const fields=[{field:"body.newPassword",message:"too short",type:"string_too_short"}];
  mock({status:422,body:{code:"validation_error",message:"Invalid",requestId:"body-id",fieldErrors:fields}});
  await assert.rejects(api.postJson("/auth/password",{},session.csrfToken),
    e=>e.code==="validation_error" && e.requestId==="body-id" && e.fieldErrors[0].field===fields[0].field);
  groups++;

  mock({body:{state:"failed",snapshot:null}});
  const observation=await api.readSwitchObservation("fixture-device");
  assert.equal(observation.snapshot,null);
  assert.equal(observation.run.state,"failed");
  assert.equal(calls.length,1);
  groups++;

  mock({body:null});
  await assert.rejects(api.readJson("/assets"),e=>e.code==="invalid_json");
  groups++;
  assert.equal(groups,13);
  console.log("mocked_fetch_groups="+groups);
}
main().catch(error=>{console.error(error);process.exitCode=1;});
"""


if __name__ == "__main__":
    unittest.main()
