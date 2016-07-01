# Branch Structure
* **master**: The latest official GA version, which is currently 5.x
* **dev**: The dev working branch of master, which is 5.x
* **dev4x**: The dev working branch of master for 4.x

If you are contributing code to 5.x, you should branch from **dev**
If you are contributing code to 4.x, you should branch from **dev4x**

## Release branches
Release tracking branches are created for each significant release. At this time, we have the following release branches:
* **release**
* **release4x**
* **Release3x**

If you want to track a branch for a specific release, use the [tag branches](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/tags).

# Filing Bugs
Please file issues you see in the [issue tracker](https://github.com/AzureAD/azure-activedirectory-identitymodel-extensions-for-dotnet/issues). Include:

 - The version you're using.
 - The behavior you're seeing. If at all possible, please submit a reduced repro or test that demonstrates the
   issue.
 - What you expect to see.

# Instructions for Contributing Code

## Contributing bug fixes

We are currently accepting contributions in the form of bug fixes. A bug must have an issue tracking it in the issue tracker. The best candidates have the tag "Accepting PRs". Your pull request should include a link to the bug that you are fixing. If you've submitted a PR for a bug, please post a comment in the bug to avoid duplication of effort.

## Contributing features
Features (things that add new or improved functionality) may be accepted, but will need to first be approved (tagged with "Enhancement" and "Accepting PRs") in the issue.

## Legal
You will need to complete a Contributor License Agreement (CLA). Briefly, this agreement testifies that you are granting us permission to use the submitted change according to the terms of the project's license, and that the work being submitted is under appropriate copyright.

Please submit a Contributor License Agreement (CLA) before submitting a pull request. You may visit https://cla.microsoft.com to sign digitally. Once we have received the signed CLA, we'll review the request.

## Housekeeping
Your pull request should:

* Include a description of what your change intends to do
* Be based on a reasonably recent pull in the correct branch
    * Please rebase and squash all commits into a single one
* Pass all tests
* Have clear commit messages
* Include new tests for new features
* To avoid line ending issues, set `autocrlf = input` and `whitespace = cr-at-eol` in your git configuration

## Building and running tests
To build and run tests, use 'build'
```Shell
>build
```

Build and test failures will appear in red in the console window.

