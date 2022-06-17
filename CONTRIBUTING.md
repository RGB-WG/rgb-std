Contributing to LNP/BP projects
===============================

:+1::tada: 
First and foremost, thanks for taking the time to contribute!
:tada::+1:

The following is a set of guidelines for contributing to [LNP/BP Standards
Association](https://lnp-bp.org) projects, which are hosted in the GitHub
organizations listed in [readme](https://github.com/LNP-BP#Working-groups).
These are mostly guidelines, not rules. Use your best judgment, and feel free to
propose changes to this document in a pull request.

#### Table Of Contents
- [General](#general)
- [Communication channels](#communication-channels)
- [Asking questions](#asking-questions)
- [Contribution workflow](#contribution-workflow)
    * [Preparing PRs](#preparing-prs)
    * [Peer review](#peer-review)
- [Coding conventions](#coding-conventions)
- [Security](#security)
- [Testing](#testing)
- [Going further](#going-further)


General
-------
The LNP/BP projects operate an open contributor model where anyone is welcome to 
contribute towards development in the form of peer review, documentation, 
testing and patches.

Anyone is invited to contribute without regard to technical experience, 
"expertise", OSS experience, age, or other concern. However, the development of 
standards & reference implementations demands a high-level of rigor, adversarial 
thinking, thorough testing and risk-minimization. Any bug may cost users real 
money. That being said, we deeply welcome people contributing for the first time 
to an open source project or pick up Rust while contributing. Don't be shy, 
you'll learn.

Communications Channels
-----------------------
Communication about LNP/BP standards & implementations happens primarily 
on #lnp-pb IRC chat on Freenode with the logs available at 
<http://gnusha.org/lnp-bp/>

Discussion about code base improvements happens in GitHub issues and on pull
requests.

Major projects are tracked [here](https://github.com/orgs/LNP-BP/projects).
Project roadmap is tracked in each repository GitHub milestones.

Asking Questions
----------------
> **Note:** Please don't file an issue to ask a question. Each repository - or
> GitHub organization has a "Discussions" with Q&A section; please post your 
> questions there. You'll get faster results by using this channel.

Alternatively, we have a dedicated developer channel on IRC, #lnp-bp@libera.chat
where you may get helpful advice if you have questions.

Contribution Workflow
---------------------
The codebase is maintained using the "contributor workflow" where everyone
without exception contributes patch proposals using "pull requests". This
facilitates social contribution, easy testing and peer review.

To contribute a patch, the workflow is a as follows:

  1. Fork Repository
  2. Create topic branch
  3. Commit patches

In general commits should be atomic and diffs should be easy to read. For this 
reason do not mix any formatting fixes or code moves with actual code changes. 
Further, each commit, individually, should compile and pass tests, in order to 
ensure git bisect and other automated tools function properly.

When adding a new feature thought must be given to the long term technical debt. 
Every new features should be covered by unit tests.

When refactoring, structure your PR to make it easy to review and don't hesitate
to split it into multiple small, focused PRs.

The Minimal Supported Rust Version is nightly for the period of active 
development; it is enforced by our Travis. Later we plan to fix to some specific 
Rust version after the initial library release.

Commits should cover both the issue fixed and the solution's rationale.
These [guidelines](https://chris.beams.io/posts/git-commit/) should be kept in 
mind.

To facilitate communication with other contributors, the project is making use 
of GitHub's "assignee" field. First check that no one is assigned and then 
comment suggesting that you're working on it. If someone is already assigned, 
don't hesitate to ask if the assigned party or previous commenters are still 
working on it if it has been awhile.

### Preparing PRs

The main library development happens in the `master` branch. This branch must 
always compile without errors (using Travis CI). All external contributions are 
made within PRs into this branch.

Prerequisites that a PR must satisfy for merging into the `master` branch:
* the tip of any PR branch must compile and pass unit tests with no errors, with
  every feature combination (including compiling the fuzztests) on MSRV, stable
  and nightly compilers (this is partially automated with CI, so the rule
  is that we will not accept commits which do not pass GitHub CI);
* contain all necessary tests for the introduced functional (either as a part of
  commits, or, more preferably, as separate commits, so that it's easy to
  reorder them during review and check that the new tests fail without the new
  code);
* contain all inline docs for newly introduced API and pass doc tests;
* be based on the recent `master` tip from the original repository at.

NB: reviewers may run more complex test/CI scripts, thus, satisfying all the
requirements above is just a preliminary, but not necessary sufficient step for
getting the PR accepted as a valid candidate PR for the `master` branch.

Additionally, to the `master` branch some repositories may have `develop` branch
for any experimental developments. This branch may not compile and should not be
used by any projects depending on the library.

### Peer review

Anyone may participate in peer review which is expressed by comments in the pull
request. Typically reviewers will review the code for obvious errors, as well as
test out the patch set and opine on the technical merits of the patch. PR should
be reviewed first on the conceptual level before focusing on code style or 
grammar fixes.

Coding Conventions
------------------
Our CI enforces [clippy's](https://github.com/rust-lang/rust-clippy) 
[default linting](https://rust-lang.github.io/rust-clippy/rust-1.52.0/index.html)
and [rustfmt](https://github.com/rust-lang/rustfmt) formatting defined by rules
in [.rustfmt.toml](./.rustfmt.toml). The linter should be run with current 
stable rust compiler, while formatter requires nightly version due to the use of
unstable formatting parameters.

If you use rustup, to lint locally you may run the following instructions:

```console
rustup component add clippy
rustup component add fmt
cargo +stable clippy --workspace --all-features
cargo +nightly fmt --all
```

Security
--------
Security is the primary focus of LNP/BP libraries; disclosure of security 
vulnerabilities helps prevent user loss of funds. If you believe a vulnerability 
may affect other implementations, please inform them. Guidelines for a 
responsible disclosure can be found in [SECURITY.md](./SECURITY.md) file in the
project root.

Note that some of LNP/BP projects are currently considered "pre-production".
Such projects can be distinguished by the absence of `SECURITY.md`. In such 
cases there are no special handling of security issues; please simply open 
an issue on GitHub.

Testing
-------
Related to the security aspect, LNP/BP developers take testing very seriously. 
Due to the modular nature of the project, writing new functional tests is easy 
and good test coverage of the codebase is an important goal.

Fuzzing is heavily encouraged: feel free to add related material under `fuzz/`

Mutation testing is planned; any contribution there would be warmly welcomed.

Going further
-------------
You may be interested in Jon Atack guide on 
[How to review Bitcoin Core PRs][Review] and [How to make Bitcoin Core PRs][PR].
While there are differences between the projects in terms of context and 
maturity, many of the suggestions offered apply to this project.

Overall, have fun :)

[Review]: https://github.com/jonatack/bitcoin-development/blob/master/how-to-review-bitcoin-core-prs.md
[PR]: https://github.com/jonatack/bitcoin-development/blob/master/how-to-make-bitcoin-core-prs.md
