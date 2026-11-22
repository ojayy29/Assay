'use strict';
// Automerge bot. Runs from .github/workflows/automerge.yml, always from the
// default branch and never from a PR's code: it fetches PR refs to diff them,
// but nothing a PR contains is ever checked out or executed here.
//
// For every open PR it decides one of:
//   MERGE   every condition is met -> squash-merge
//   WAIT    nothing is wrong, CI is still running -> do nothing
//   BLOCKED the contributor has something to fix -> sticky comment saying what
//   HOLD    a maintainer must look (merge gate / workflow approval) -> sticky comment
//
// It also approves "action_required" workflow runs from first-time contributors
// so CI can start, unless the PR changes files CI itself executes from the PR
// (workflows, scripts); those wait for a maintainer.

const { execFileSync, spawnSync } = require('child_process');

const MARKER = '<!-- assay-automerge -->';

// Required contexts come from the live branch ruleset (see requiredContexts),
// so this list can never drift from what GitHub enforces. It is only the
// fallback if the ruleset cannot be read, and MALWARE_CONTEXT is always added.
const FALLBACK_REQUIRED = ['Go', 'golangci-lint', 'Soroban contract', 'Merge gate'];

// Published by .github/workflows/malware-scan.yml as a commit status. The bot
// does not scan anything itself: it requires that scan, and never starts CI
// for a PR before it has passed.
const MALWARE_CONTEXT = 'Malware scan';

const OPT_OUT_LABEL = 'no-automerge';
const REVIEW_LABEL = 'needs-maintainer-review';
const SECURITY_LABEL = 'security-hold'; // set and cleared by malware-scan.yml; read-only here
const MERGE_METHOD = 'squash';

// CI runs these straight out of the PR checkout, so a PR that edits them could
// run different code than the repo's. Don't approve a run for such a PR.
const UNSAFE_TO_AUTO_APPROVE = ['.github/', 'scripts/'];

const REPO_URL = `https://github.com/${process.env.GITHUB_REPOSITORY}`;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const git = (args) => execFileSync('git', args, { encoding: 'utf8' });

module.exports = async function automerge({ github, context, core }) {
  const { owner, repo } = context.repo;
  const dryRun = process.env.DRY_RUN === 'true';
  const defaultBranch = context.payload.repository.default_branch;

  // Every side effect goes through here so a dry run changes nothing.
  const act = async (what, fn) => {
    if (dryRun) {
      core.info(`[dry run] would: ${what}`);
      return undefined;
    }
    core.info(what);
    return fn();
  };

  const openPrs = await github.paginate(github.rest.pulls.list, {
    owner, repo, state: 'open', base: defaultBranch, per_page: 100,
  });

  // 1. Let CI start for PRs that are safe to run.
  const refusals = await approvePendingRuns({ github, core, owner, repo, openPrs, act });

  // 2. Evaluate. A PR event only needs its own PR; everything else sweeps.
  let targets = openPrs;
  if (context.eventName === 'pull_request_target') {
    targets = openPrs.filter((p) => p.number === context.payload.pull_request.number);
  }

  for (const listed of targets) {
    try {
      await handle({ github, core, owner, repo, defaultBranch, listed, refusals, act });
    } catch (err) {
      // One broken PR must not stop the sweep for the rest.
      core.warning(`#${listed.number}: ${err.stack || err}`);
    }
  }
};

// ---------------------------------------------------------------- approvals

async function approvePendingRuns({ github, core, owner, repo, openPrs, act }) {
  const refusals = new Map(); // head sha -> paths that need a maintainer to approve the run
  const runs = await github.paginate(github.rest.actions.listWorkflowRunsForRepo, {
    owner, repo, status: 'action_required', per_page: 100,
  });

  for (const run of runs) {
    if (run.event !== 'pull_request') continue;
    const pr = openPrs.find((p) => p.head.sha === run.head_sha);
    if (!pr) continue;

    // Approving a run executes the PR's code, so the malware scan must have
    // passed on this exact commit first. Anything else waits for the next sweep.
    const scan = (await statusesFor(github, owner, repo, run.head_sha)).get(MALWARE_CONTEXT);
    if (!scan || scan.state !== 'success') {
      core.info(`#${pr.number}: not approving run ${run.id}; ${MALWARE_CONTEXT} is ${scan ? scan.state : 'not reported yet'}`);
      continue;
    }

    const names = await changedPaths(github, owner, repo, pr.number);
    const risky = names.filter((f) => UNSAFE_TO_AUTO_APPROVE.some((p) => f.startsWith(p)));
    if (risky.length > 0) {
      refusals.set(run.head_sha, risky);
      core.info(`#${pr.number}: not approving run ${run.id}; touches ${risky.join(', ')}`);
      continue;
    }
    try {
      await act(`approve workflow run ${run.id} (${run.name}) for #${pr.number}`, () =>
        github.rest.actions.approveWorkflowRun({ owner, repo, run_id: run.id }));
    } catch (err) {
      core.warning(`could not approve run ${run.id}: ${err.message}`);
    }
  }
  return refusals;
}

async function changedPaths(github, owner, repo, number) {
  const files = await github.paginate(github.rest.pulls.listFiles, {
    owner, repo, pull_number: number, per_page: 100,
  });
  return files.flatMap((f) => (f.previous_filename ? [f.filename, f.previous_filename] : [f.filename]));
}

// Latest commit status per context on a sha: Map(context -> {state, target_url, description}).
async function statusesFor(github, owner, repo, ref) {
  const { data } = await github.rest.repos.getCombinedStatusForRef({ owner, repo, ref, per_page: 100 });
  return new Map(data.statuses.map((s) => [s.context, s]));
}

// The contexts the branch ruleset requires, read live. Falls back to a fixed list.
async function requiredContexts(github, core, owner, repo, branch) {
  let names = FALLBACK_REQUIRED;
  try {
    const { data } = await github.request('GET /repos/{owner}/{repo}/rules/branches/{branch}', { owner, repo, branch });
    const found = data.filter((r) => r.type === 'required_status_checks')
      .flatMap((r) => r.parameters.required_status_checks.map((c) => c.context));
    if (found.length > 0) names = found;
  } catch (err) {
    core.warning(`could not read the branch ruleset (${err.message}); using the fallback list`);
  }
  return [...new Set([...names, MALWARE_CONTEXT])];
}

// ----------------------------------------------------------------- per PR

async function handle({ github, core, owner, repo, defaultBranch, listed, refusals, act }) {
  const n = listed.number;
  const labels = listed.labels.map((l) => l.name);

  if (listed.draft) return core.info(`#${n}: draft, skipping`);
  if (labels.includes(OPT_OUT_LABEL)) return core.info(`#${n}: labelled ${OPT_OUT_LABEL}, skipping`);

  const pr = await getPrWithMergeability(github, owner, repo, n);
  const ev = await evaluate({ github, core, owner, repo, defaultBranch, pr, refusals });

  // A malware-scan failure outranks everything and is never overridden by approval.
  const state = ev.security.length > 0 ? 'SECURITY'
    : ev.blockers.length > 0 ? 'BLOCKED'
    : ev.holds.length > 0 ? 'HOLD'
    : ev.pending.length > 0 ? 'WAIT' : 'MERGE';
  core.info(`#${n}: ${state}`);

  const wantReviewLabel = ev.holds.length > 0;
  await syncLabel({ github, owner, repo, n, labels, name: REVIEW_LABEL, want: wantReviewLabel, act });

  if (state === 'MERGE') {
    try {
      await act(`squash-merge #${n} at ${pr.head.sha}`, () =>
        github.rest.pulls.merge({
          owner, repo, pull_number: n, merge_method: MERGE_METHOD,
          sha: pr.head.sha, // refuses if the PR moved since we evaluated it
          commit_title: `${pr.title} (#${n})`,
        }));
      await upsertComment({ github, owner, repo, n, act, body: renderMerged(pr) });
    } catch (err) {
      core.warning(`#${n}: merge failed: ${err.message}`);
      ev.holds.push({
        title: 'The bot could not complete the merge',
        detail: `GitHub refused: \`${err.message}\`. A maintainer needs to look; nothing is required from you unless this says otherwise.`,
      });
      await upsertComment({ github, owner, repo, n, act, body: render(pr, ev, 'HOLD') });
    }
    return;
  }

  if (state === 'WAIT') {
    // Only touch an existing comment, so a stale "failing" message is replaced.
    await upsertComment({ github, owner, repo, n, act, body: render(pr, ev, 'WAIT'), onlyIfExists: true });
    return;
  }
  await upsertComment({ github, owner, repo, n, act, body: render(pr, ev, state) });
}

async function getPrWithMergeability(github, owner, repo, n) {
  // `mergeable` is computed lazily and is null until GitHub gets to it.
  let pr;
  for (let i = 0; i < 6; i++) {
    ({ data: pr } = await github.rest.pulls.get({ owner, repo, pull_number: n }));
    if (pr.mergeable !== null) break;
    await sleep(2000);
  }
  return pr;
}

// --------------------------------------------------------------- evaluation

async function evaluate({ github, core, owner, repo, defaultBranch, pr, refusals }) {
  const n = pr.number;
  const security = []; // malware screen findings: never auto-merged
  const blockers = []; // contributor can fix
  const holds = [];    // maintainer must act
  const pending = [];  // just waiting

  // Merge conflicts.
  if (pr.mergeable === false) {
    blockers.push({
      title: `Merge conflicts with \`${defaultBranch}\``,
      detail: `Update your branch (\`git fetch upstream && git rebase upstream/${defaultBranch}\`, or merge it in) and resolve the conflicts, then push.`,
    });
  } else if (pr.mergeable === null) {
    pending.push('GitHub is still computing whether this merges cleanly');
  }

  // Required checks on the exact head commit: Actions check runs and commit statuses.
  const runs = await github.paginate(github.rest.checks.listForRef, {
    owner, repo, ref: pr.head.sha, per_page: 100,
  });
  const statuses = await statusesFor(github, owner, repo, pr.head.sha);
  for (const name of await requiredContexts(github, core, owner, repo, defaultBranch)) {
    const run = runs.filter((r) => r.name === name).sort((a, b) => b.id - a.id)[0];
    const st = statuses.get(name);
    let state; let url; let note = '';
    if (run) {
      state = run.status !== 'completed' ? 'pending' : run.conclusion === 'success' ? 'success' : 'failure';
      url = run.html_url; note = run.conclusion;
      if (run.output && run.output.title) note += ` (${run.output.title})`;
    } else if (st) {
      state = st.state; url = st.target_url; note = st.description || st.state;
    } else {
      state = 'pending';
    }
    if (state === 'success') continue;
    if (state === 'pending') { pending.push(name === MALWARE_CONTEXT ? 'the malware scan' : `CI check \`${name}\``); continue; }

    if (name === MALWARE_CONTEXT) {
      // failure = flagged; error = the scan itself could not finish (fail-closed).
      (state === 'failure' ? security : holds).push({
        title: state === 'failure' ? 'The malware scan flagged this PR' : 'The malware scan could not complete',
        detail: `${note}. ${url ? `[Scan run](${url}). ` : ''}${state === 'failure'
          ? 'The scan\'s own comment lists what matched. It is a screen, not a verdict: a maintainer reads the change and decides.'
          : 'A maintainer needs to re-run it.'}`,
      });
    } else {
      blockers.push({
        title: `CI check \`${name}\` ${state === 'failure' ? 'failed' : state}`,
        detail: `${note ? note + '. ' : ''}${url ? `See the [failing run](${url}). ` : ''}Reproduce locally with \`make test\` / \`make lint\` (Rust: \`make contract-lint\`, \`make contract-test\`) and push a fix.`,
      });
    }
  }
  if (pr.labels.some((l) => l.name === SECURITY_LABEL) && security.length === 0) {
    security.push({ title: `Labelled \`${SECURITY_LABEL}\``, detail: 'A maintainer must clear this label before the bot will merge.' });
  }
  const refused = refusals.get(pr.head.sha);
  if (refused && refused.length > 0) {
    holds.push({
      title: 'CI has not been started for this PR',
      detail: `It changes ${refused.map((f) => `\`${f}\``).join(', ')}, which CI executes straight from the PR, so the bot will not approve the run on its own. A maintainer must review those files and approve the workflow run. Nothing is required from you.`,
    });
  }

  // If CI was never started, "still running" would be a lie.
  if (refusals.has(pr.head.sha)) {
    for (let i = pending.length - 1; i >= 0; i--) if (pending[i].startsWith('CI check')) pending.splice(i, 1);
  }

  // Reviews.
  const reviews = await github.paginate(github.rest.pulls.listReviews, {
    owner, repo, pull_number: n, per_page: 100,
  });
  const latest = new Map(); // reviewer -> their latest decisive review
  for (const r of reviews) {
    if (r.user && ['APPROVED', 'CHANGES_REQUESTED', 'DISMISSED'].includes(r.state)) latest.set(r.user.login, r);
  }
  for (const [login, r] of latest) {
    if (r.state === 'CHANGES_REQUESTED') {
      blockers.push({
        title: `Changes requested by @${login}`,
        detail: `Address [their review](${r.html_url}) and push, then ask them to re-review or dismiss it.`,
      });
    }
  }

  // Unresolved review conversations.
  const threads = await github.graphql(
    `query($owner:String!,$repo:String!,$n:Int!){repository(owner:$owner,name:$repo){pullRequest(number:$n){
       reviewThreads(first:100){nodes{isResolved comments(first:1){nodes{url path}}}}}}}`,
    { owner, repo, n });
  const unresolved = threads.repository.pullRequest.reviewThreads.nodes.filter((t) => !t.isResolved);
  if (unresolved.length > 0) {
    const links = unresolved.slice(0, 10).map((t) => {
      const c = t.comments.nodes[0];
      return c ? `[\`${c.path}\`](${c.url})` : 'a thread';
    });
    blockers.push({
      title: `${unresolved.length} unresolved review conversation${unresolved.length > 1 ? 's' : ''}`,
      detail: `Reply and mark resolved once handled: ${links.join(', ')}.`,
    });
  }

  // PR template: described and checklist ticked. The gate cannot check these.
  blockers.push(...checkBody(pr.body));

  // The repo's merge gate, run from the default branch's copy of the script.
  const gate = runGate(core, n, pr.head.sha, defaultBranch);
  if (gate.status === 'stale') {
    pending.push('the PR head moved while it was being checked');
  } else if (gate.status === 'error') {
    holds.push({
      title: 'The merge gate could not run',
      detail: `Its finding is unknown, so the bot will not merge: \`${gate.message}\`. Nothing is required from you.`,
    });
  } else if (gate.status === 'hold') {
    const approver = await maintainerApproval({ github, owner, repo, pr, latest });
    if (approver) {
      core.info(`#${n}: gate hold satisfied by @${approver}`);
    } else {
      holds.push({
        title: 'Touches maintainer-owned paths or dependency files',
        detail: `${gate.paths.map((p) => `\`${p}\``).join(', ')}. The [merge gate](${REPO_URL}/blob/${defaultBranch}/scripts/merge-gate.sh) keeps changes here for human review: they change what a verdict means or add supply-chain trust. This is not a verdict on your work, and nothing is required from you. Once a maintainer approves the **latest commit**, the bot merges it. A new push clears that approval.`,
      });
    }
  }

  return { security, blockers, holds, pending };
}

function checkBody(body) {
  const out = [];
  const text = (body || '').replace(/<!--[\s\S]*?-->/g, '');

  // Text between the "What changed and why" heading and the next heading.
  const heading = text.match(/^##[ \t]*What changed and why[ \t]*$/im);
  let described = '';
  if (heading) {
    const rest = text.slice(heading.index + heading[0].length);
    const next = rest.search(/^##\s/m);
    described = next === -1 ? rest : rest.slice(0, next);
  }
  if (described.trim() === '') {
    out.push({
      title: 'The PR description does not say what changed and why',
      detail: 'Fill in the "What changed and why" section of the PR template.',
    });
  }

  const unticked = [...text.matchAll(/^[ \t]*[-*][ \t]+\[ \][ \t]+(.+)$/gm)].map((m) => m[1].replace(/\*\*/g, '').trim());
  const ticked = [...text.matchAll(/^[ \t]*[-*][ \t]+\[[xX]\][ \t]+/gm)];
  if (unticked.length + ticked.length === 0) {
    out.push({
      title: 'The PR checklist is missing',
      detail: `Restore the checklist from [the PR template](${REPO_URL}/blob/HEAD/.github/PULL_REQUEST_TEMPLATE.md) and tick each item that is true.`,
    });
  } else if (unticked.length > 0) {
    out.push({
      title: `${unticked.length} checklist item${unticked.length > 1 ? 's' : ''} not ticked`,
      detail: unticked.map((t) => `\n   - ${t.length > 110 ? t.slice(0, 107) + '...' : t}`).join('') +
        '\n   Tick each box you can honestly stand behind, or explain in the description why one does not apply.',
    });
  }
  return out;
}

// Runs scripts/merge-gate.sh (the default branch's copy) over the PR's commits.
function runGate(core, n, headSha, defaultBranch) {
  try {
    git(['fetch', '--no-tags', '--quiet', 'origin', `+refs/pull/${n}/head:refs/remotes/pr/${n}`]);
    if (git(['rev-parse', `refs/remotes/pr/${n}`]).trim() !== headSha) return { status: 'stale' };
    const base = git(['merge-base', `origin/${defaultBranch}`, headSha]).trim();
    const r = spawnSync('./scripts/merge-gate.sh', [base, headSha], { encoding: 'utf8' });
    if (r.status === 0) return { status: 'clean' };
    if (r.status === 1) {
      const paths = r.stdout.split('\n').filter((l) => /^ {2}\S/.test(l)).map((l) => l.trim());
      return { status: 'hold', paths };
    }
    return { status: 'error', message: `exit ${r.status}: ${(r.stderr || r.stdout).trim().slice(0, 300)}` };
  } catch (err) {
    core.warning(`gate failed for #${n}: ${err.message}`);
    return { status: 'error', message: String(err.message).slice(0, 300) };
  }
}

// A held PR may merge once someone with write access approved the current head.
async function maintainerApproval({ github, owner, repo, pr, latest }) {
  for (const [login, r] of latest) {
    if (r.state !== 'APPROVED' || r.commit_id !== pr.head.sha || login === pr.user.login) continue;
    try {
      const { data } = await github.rest.repos.getCollaboratorPermissionLevel({ owner, repo, username: login });
      if (['admin', 'write'].includes(data.permission)) return login;
    } catch (_) { /* not a collaborator */ }
  }
  return null;
}

// ----------------------------------------------------------------- comments

function render(pr, ev, state) {
  const sha = pr.head.sha.slice(0, 7);
  const lines = [MARKER];
  if (state === 'WAIT') {
    lines.push('### Automerge: nothing left for you to fix', '',
      `@${pr.user.login}, the earlier problems are resolved. Still waiting on: ${ev.pending.join(', ')}. This merges automatically once those pass.`);
  } else {
    lines.push('### Automerge: this PR is not ready to merge yet', '',
      `Thanks @${pr.user.login}. The bot checked \`${sha}\` and these conditions are not met.`);
    if (ev.security.length > 0) {
      lines.push('', '**Held for security review**', '');
      ev.security.forEach((b, i) => lines.push(`${i + 1}. **${b.title}**: ${b.detail}`));
      lines.push('', 'The bot will not start CI or merge this PR itself; a maintainer decides.');
    }
    if (ev.blockers.length > 0) {
      lines.push('', '**For you to fix**', '');
      ev.blockers.forEach((b, i) => lines.push(`${i + 1}. **${b.title}**: ${b.detail}`));
    }
    if (ev.holds.length > 0) {
      lines.push('', '**Waiting on a maintainer**', '');
      ev.holds.forEach((b, i) => lines.push(`${i + 1}. **${b.title}**: ${b.detail}`));
    }
    if (ev.pending.length > 0) lines.push('', `Also still running: ${ev.pending.join(', ')}.`);
  }
  lines.push('', '<sub>This comment updates itself on every push and re-check, so there is no need to ping anyone. ' +
    `To opt a PR out of automerge, add the \`${OPT_OUT_LABEL}\` label.</sub>`);
  return lines.join('\n');
}

function renderMerged(pr) {
  return `${MARKER}\n### Automerge: merged\n\nAll conditions were met for \`${pr.head.sha.slice(0, 7)}\` (CI green, merge gate clear, checklist complete, no open review conversations). Squash-merged. Thanks @${pr.user.login}!`;
}

async function upsertComment({ github, owner, repo, n, body, act, onlyIfExists = false }) {
  if (process.env.DRY_RUN === 'true') console.log(`---- comment body for #${n}\n${body}\n----`);
  const comments = await github.paginate(github.rest.issues.listComments, {
    owner, repo, issue_number: n, per_page: 100,
  });
  // Only trust our own comments; anyone can paste the marker.
  const mine = comments.find((c) => c.body.startsWith(MARKER) &&
    (c.user.type === 'Bot' || c.user.login === process.env.AUTOMERGE_BOT_LOGIN));
  if (mine) {
    if (mine.body === body) return;
    return act(`update comment on #${n}`, () =>
      github.rest.issues.updateComment({ owner, repo, comment_id: mine.id, body }));
  }
  if (onlyIfExists) return;
  return act(`comment on #${n}`, () =>
    github.rest.issues.createComment({ owner, repo, issue_number: n, body }));
}

async function syncLabel({ github, owner, repo, n, labels, name, want, act }) {
  const has = labels.includes(name);
  if (want && !has) {
    await act(`label #${n} ${name}`, () => github.rest.issues.addLabels({ owner, repo, issue_number: n, labels: [name] }));
  } else if (!want && has) {
    await act(`unlabel #${n} ${name}`, () => github.rest.issues.removeLabel({ owner, repo, issue_number: n, name }));
  }
}
