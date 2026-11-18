const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
const workflow = fs.readFileSync(
  path.join(__dirname, "../workflows/sonar.yml"),
  "utf8",
);
const scripts = [
  ...workflow.matchAll(
    /          script: \|\n((?:            .*\n|[ \t]*\n)+)/g,
  ),
].map((match) =>
  match[1]
    .split("\n")
    .map((line) => line.slice(12))
    .join("\n"),
);
const metadata = new AsyncFunction("github", "context", "core", scripts[0]);
const publish = new AsyncFunction("github", "context", "core", scripts.at(-1));
const head = "a".repeat(40),
  base = "b".repeat(40),
  ancestor = "c".repeat(40);
function fixture(options = {}) {
  const run = {
    id: 10,
    path: ".github/workflows/analysis-inputs.yml",
    head_sha: head,
    event: "pull_request",
    conclusion: "success",
  };
  const pr = {
    number: 69,
    state: "open",
    head: {
      sha: head,
      ref: "feature",
      repo: {
        full_name: "timlaing/net-admin",
        owner: { login: "timlaing" },
        name: "net-admin",
      },
    },
    base: { sha: base, ref: "main", repo: { full_name: "timlaing/net-admin" } },
  };
  const statuses = [],
    reads = [];
  const context = {
    repo: { owner: "timlaing", repo: "net-admin" },
    payload: { workflow_run: run },
    eventName: "workflow_run",
    actor: "writer",
    sha: base,
    ref: "refs/heads/main",
    serverUrl: "https://github.com",
    runId: 100,
    ...options.context,
  };
  if (context.eventName === "workflow_dispatch") context.payload = {};
  const github = {
    paginate: async () => [pr],
    rest: {
      actions: { getWorkflowRun: async () => ({ data: run }) },
      repos: {
        listPullRequestsAssociatedWithCommit: () => {},
        compareCommitsWithBasehead: async (args) => {
          assert.equal(args.basehead, `${base}...${head}`);
          return { data: { merge_base_commit: { sha: ancestor } } };
        },
        getContent: async (args) => {
          reads.push(args);
          if (options.apiError)
            throw Object.assign(new Error("API failed"), {
              status: options.apiError,
            });
          const changed =
            (options.changed || options.changedPath === args.path) &&
            args.ref === head;
          const reusable =
            options.reusable && args.path.endsWith("analysis-inputs.yml");
          return {
            data: {
              type: options.symlink ? "symlink" : "file",
              encoding: "base64",
              size: 80,
              sha: changed ? "different" : args.path,
              content: Buffer.from(
                reusable
                  ? "jobs:\n  child:\n    uses: ./.github/workflows/native.yml\n"
                  : "jobs: {}",
              ).toString("base64"),
            },
          };
        },
        createCommitStatus: async (args) => statuses.push(args),
      },
      pulls: { get: async () => ({ data: { ...pr, ...options.current } }) },
    },
  };
  return {
    github,
    context,
    core: {
      setOutput: () => {},
      setFailed: (message) => {
        throw new Error(message);
      },
    },
    statuses,
    reads,
  };
}
test("unchanged producer and local reusable definitions pass using the merge base", async () => {
  const f = fixture({ reusable: true });
  await metadata(f.github, f.context, f.core);
  assert.equal(f.reads.length, 4);
  assert.equal(f.statuses[0].state, "pending");
});
test("changed recipes, symlinks and missing/unavailable API data fail before publishing", async () => {
  for (const options of [
    { reusable: true, changedPath: ".github/workflows/native.yml" },
    { changed: true },
    { symlink: true },
    { apiError: 404 },
    { apiError: 500 },
  ]) {
    const f = fixture(options);
    await assert.rejects(metadata(f.github, f.context, f.core));
    assert.equal(f.statuses.length, 0);
  }
});
test("recipe changes require exact owner dispatch; other writers and older refs fail", async () => {
  const saved = process.env.SOURCE_REVISION;
  process.env.SOURCE_REVISION = head;
  try {
    const owner = {
      eventName: "workflow_dispatch",
      actor: "timlaing",
      sha: head,
      ref: "refs/heads/feature",
    };
    const f = fixture({ changed: true, context: owner });
    await metadata(f.github, f.context, f.core);
    assert.equal(f.reads.length, 0);
    for (const context of [
      { ...owner, actor: "writer" },
      { ...owner, sha: base },
      { ...owner, ref: "refs/heads/main" },
    ]) {
      const rejected = fixture({ changed: true, context });
      await assert.rejects(
        metadata(rejected.github, rejected.context, rejected.core),
        /producer changed/,
      );
    }
  } finally {
    if (saved === undefined) delete process.env.SOURCE_REVISION;
    else process.env.SOURCE_REVISION = saved;
  }
});
test("final analysis success rechecks the open PR head and target", async () => {
  const saved = { ...process.env };
  Object.assign(process.env, {
    RESULT: "success",
    HEAD_SHA: head,
    PR_NUMBER: "69",
  });
  try {
    const valid = fixture();
    await publish(valid.github, valid.context, valid.core);
    assert.equal(valid.statuses[0].state, "success");
    for (const current of [
      { state: "closed" },
      { head: { sha: base } },
      { base: { ref: "develop" } },
    ]) {
      const f = fixture({ current });
      await assert.rejects(publish(f.github, f.context, f.core), /PR changed/);
      assert.equal(f.statuses.length, 0);
    }
  } finally {
    for (const key of ["RESULT", "HEAD_SHA", "PR_NUMBER"]) {
      if (saved[key] === undefined) delete process.env[key];
      else process.env[key] = saved[key];
    }
  }
});
