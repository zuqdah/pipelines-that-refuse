#Requires -Version 7.0

<#
    .SYNOPSIS
    Attempts every bypass in guard-matrix.json against a live Azure DevOps
    project and grades what happened against what was declared.

    .DESCRIPTION
    The drill acts as four separate identities, because the interesting guards
    cannot be driven by one: a submitter cannot approve their own pull request,
    an outstanding rejection needs a second voter, and proving the policy
    exemption works needs an identity that holds it while the others do not.

    Nothing here decides what an observation MEANS. Every classification is
    delegated to the PipelineGuards module, which has no network access and is
    covered by unit tests, so the judgement can be audited without an
    organization. This script's only job is to perform the attempts faithfully
    and record what came back.

    It holds no secret. Each identity's Azure DevOps token is obtained by
    exchanging the OIDC token GitHub Actions mints for this job, so there is
    nothing long-lived to leak -- which matters more than usual in a lab whose
    subject is delivery controls that are trusted without being tested.
#>

[CmdletBinding()]
param(
    # terraform output -json, so the drill reads ids, client ids and pipeline
    # numbers from the apply that produced them rather than from arguments a
    # workflow could pass inconsistently.
    [Parameter(Mandatory)]
    [string] $TerraformOutput,

    [Parameter(Mandatory)]
    [ValidateSet('permissive', 'hardened')]
    [string] $Pass,

    [Parameter()]
    [string] $MatrixPath = (Join-Path -Path $PSScriptRoot -ChildPath '../guard-matrix.json'),

    [Parameter()]
    [string] $ReportPath = 'guard-report.json',

    [Parameter()]
    [string] $MarkdownPath = 'guard-report.md',

    # How long to wait for a queued pipeline to reach a state worth reading.
    [Parameter()]
    [int] $PipelineTimeoutSeconds = 600
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
# Write-Information is the house style for progress in this series, but it is
# silent by default -- a run reporting nothing would look like a run doing
# nothing.
$InformationPreference = 'Continue'

Import-Module (Join-Path -Path $PSScriptRoot -ChildPath '../module/PipelineGuards/PipelineGuards.psm1') -Force

# The Azure DevOps resource id. Constant across every tenant; it is the
# application id of Azure DevOps itself.
$script:AdoResource = '499b84ac-1321-427f-aa17-267ca6975798'
$script:ApiVersion = '7.1'

# One constant is not enough. Azure DevOps ships some endpoints as GA at 7.1
# and others as preview only, and asking for the wrong one is a 400 whose
# message names the version rather than anything about the request:
#
#   The requested version "7.1" of the resource is under preview. The -preview
#   flag must be supplied in the api-version for such requests.
#
# connectionData is preview; projects, builds, pull requests and pipeline runs
# are not. This was found by calling connectionData against the real
# organization, where it would otherwise have failed on the live run and been
# read as an authentication problem.
$script:PreviewApiVersion = '7.1-preview'

# ---------------------------------------------------------------- terraform

$tfRaw = [System.IO.File]::ReadAllText($TerraformOutput)
if ([string]::IsNullOrWhiteSpace($tfRaw)) {
    throw "Terraform output at '$TerraformOutput' is empty. The drill cannot invent the ids it is meant to act on."
}
$tf = $tfRaw | ConvertFrom-Json

function Get-TfValue {
    param([Parameter(Mandatory)][string] $Name)
    if (-not ($tf.PSObject.Properties.Name -contains $Name)) {
        throw "Terraform output has no '$Name'. Either the apply did not finish or infra/outputs.tf changed without this script."
    }
    return $tf.$Name.value
}

$organization = Get-TfValue 'organization_url'
$projectName = Get-TfValue 'project_name'
$repositoryId = Get-TfValue 'repository_id'
$repositoryUrl = Get-TfValue 'repository_web_url'
$defaultBranch = Get-TfValue 'default_branch'
$environmentName = Get-TfValue 'environment_name'
$clientIds = Get-TfValue 'identity_client_ids'
$tenantId = Get-TfValue 'tenant_id'
$pipelineIds = Get-TfValue 'build_definition_ids'
$drillSecret = Get-TfValue 'drill_secret'
$appliedPolicy = Get-TfValue 'policy_settings_applied'

# The pass the drill was told to grade against has to match the configuration
# that is actually applied, or every diverging guard is graded against the
# wrong expectation and the report is confidently wrong. Two of the applied
# settings encode the pass, so they are checked rather than trusted.
$appliedIsHardened = [bool]$appliedPolicy.on_push_reset_approved_votes
$expectedHardened = $Pass -eq 'hardened'
if ($appliedIsHardened -ne $expectedHardened) {
    throw ("Told to grade the '$Pass' pass, but the applied policy has " +
        "on_push_reset_approved_votes=$appliedIsHardened. Grading would compare live " +
        'results against the wrong column. Re-apply with the matching pass, or fix the argument.')
}

$branchShort = $defaultBranch -replace '^refs/heads/', ''

# ------------------------------------------------------------------- tokens

function Get-GitHubOidcToken {
    <#
        .SYNOPSIS
        The token GitHub Actions mints for this job, used as a client assertion.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param()

    $url = $env:ACTIONS_ID_TOKEN_REQUEST_URL
    $requestToken = $env:ACTIONS_ID_TOKEN_REQUEST_TOKEN
    if ([string]::IsNullOrWhiteSpace($url) -or [string]::IsNullOrWhiteSpace($requestToken)) {
        throw 'No GitHub OIDC request URL or token in the environment. The job needs "permissions: id-token: write"; without it the drill has no way to authenticate and would report every guard as AuthFailure, which looks like a very well protected repository.'
    }

    $response = Invoke-RestMethod -Method Get -Uri "$url&audience=api://AzureADTokenExchange" `
        -Headers @{ Authorization = "Bearer $requestToken" }
    return $response.value
}

function Get-AdoToken {
    <#
        .SYNOPSIS
        Exchanges the GitHub assertion for an Azure DevOps access token.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param(
        [Parameter(Mandatory)][string] $ClientId,
        [Parameter(Mandatory)][string] $Assertion
    )

    $body = @{
        client_id             = $ClientId
        scope                 = "$script:AdoResource/.default"
        grant_type            = 'client_credentials'
        client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
        client_assertion      = $Assertion
    }

    try {
        $response = Invoke-RestMethod -Method Post `
            -Uri "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token" `
            -ContentType 'application/x-www-form-urlencoded' -Body $body
        return $response.access_token
    } catch {
        # Federated credential propagation takes a few minutes in Entra, and the
        # error for a credential that does not exist yet is indistinguishable
        # from one for a subject that will never match. Saying so here beats
        # eleven AuthFailure results.
        throw "Could not get an Azure DevOps token for client $ClientId. If the federated credential was just created, Entra takes about three minutes to propagate. Underlying error: $($_.Exception.Message)"
    }
}

$assertion = Get-GitHubOidcToken

$tokens = @{}
foreach ($name in $clientIds.PSObject.Properties.Name) {
    $tokens[$name] = Get-AdoToken -ClientId $clientIds.$name -Assertion $assertion
    Write-Information "Authenticated as '$name'."
}

# ---------------------------------------------------------------- rest calls

function Invoke-Ado {
    <#
        .SYNOPSIS
        Calls the Azure DevOps REST API and returns the status code alongside
        the body, without throwing on a non-2xx response.

        .DESCRIPTION
        A refusal is the thing being measured here, so a 409 is data rather
        than an error. Letting Invoke-RestMethod throw would turn every
        successful guard into an exception and every classification into
        exception-message parsing.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string] $Identity,
        [Parameter(Mandatory)][string] $Uri,
        [Parameter()][string] $Method = 'Get',
        [Parameter()][object] $Body
    )

    $params = @{
        Method                  = $Method
        Uri                     = $Uri
        Headers                 = @{ Authorization = "Bearer $($tokens[$Identity])" }
        SkipHttpErrorCheck      = $true
        StatusCodeVariable      = 'status'
        ErrorAction             = 'Stop'
        MaximumRedirection      = 0
    }
    if ($null -ne $Body) {
        $params['ContentType'] = 'application/json'
        $params['Body'] = ($Body | ConvertTo-Json -Depth 10 -Compress)
    }

    $response = Invoke-RestMethod @params
    return [pscustomobject]@{
        StatusCode = $status
        Body       = $response
        Raw        = if ($null -ne $response) { ($response | ConvertTo-Json -Depth 6 -Compress) } else { '' }
    }
}

function Get-AdoIdentityId {
    <#
        .SYNOPSIS
        The identity id Azure DevOps knows a token by.

        .DESCRIPTION
        Needed to cast a vote, which addresses a reviewer by id. Read from
        connectionData rather than passed in from Terraform, because Terraform
        exposes the graph descriptor and the pull request API wants the GUID --
        two different identifiers for the same subject, and using the wrong one
        returns a cheerful 200 having reviewed nothing.
    #>
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][string] $Identity)

    $result = Invoke-Ado -Identity $Identity -Uri "$organization/_apis/connectionData?api-version=$script:PreviewApiVersion"
    if ($result.StatusCode -ne 200) {
        throw "connectionData returned $($result.StatusCode) for '$Identity'. Without an identity id this drill cannot vote, and a guard that cannot run must fail rather than pass quietly."
    }
    $id = $result.Body.authenticatedUser.id
    if ([string]::IsNullOrWhiteSpace($id)) {
        throw "connectionData returned no authenticatedUser.id for '$Identity'."
    }
    return $id
}

# ------------------------------------------------------------------- git

function Invoke-Git {
    <#
        .SYNOPSIS
        Runs git as one of the drill identities and returns exit code and stderr.

        .DESCRIPTION
        The token goes in through GIT_CONFIG_* environment variables rather than
        `git -c http.extraheader=...`, which would put a bearer token in the
        process arguments where any other process on the machine can read it.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][string] $Identity,
        [Parameter(Mandatory)][string[]] $Arguments,
        [Parameter()][string] $WorkingDirectory
    )

    $previous = @{}
    $vars = @{
        GIT_CONFIG_COUNT       = '2'
        GIT_CONFIG_KEY_0       = 'http.extraheader'
        GIT_CONFIG_VALUE_0     = "AUTHORIZATION: bearer $($tokens[$Identity])"
        GIT_CONFIG_KEY_1       = 'credential.helper'
        GIT_CONFIG_VALUE_1     = ''
        GIT_TERMINAL_PROMPT    = '0'
        GIT_ASKPASS            = ''
    }
    foreach ($key in $vars.Keys) {
        $previous[$key] = [Environment]::GetEnvironmentVariable($key)
        [Environment]::SetEnvironmentVariable($key, $vars[$key])
    }

    # ProcessStartInfo.ArgumentList, not Start-Process -ArgumentList.
    #
    # Start-Process joins an argument array into a single command line without
    # quoting, so any argument containing a space is split into several. Passing
    # @('commit', '-am', 'Attempt a direct push') made git see
    #   commit -am Attempt a direct push
    # take "Attempt" as the whole message, and treat the remaining words as
    # PATHS -- "fatal: paths 'a ...' with -a does not make sense".
    #
    # Every commit therefore failed, every push had nothing to send, and every
    # push exited zero with "Everything up-to-date", which the classifier read
    # as a protected branch letting a push through. One unquoted space produced
    # four confidently wrong guard results.
    #
    # ArgumentList on ProcessStartInfo escapes each element properly.
    try {
        $psi = [System.Diagnostics.ProcessStartInfo]::new('git')
        foreach ($argument in $Arguments) { $psi.ArgumentList.Add($argument) }
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.UseShellExecute = $false
        if ($WorkingDirectory) { $psi.WorkingDirectory = $WorkingDirectory }

        $process = [System.Diagnostics.Process]::Start($psi)

        # Read both streams asynchronously before waiting. Reading one to the
        # end first deadlocks if the other fills its buffer, which git will do
        # on a verbose push.
        $outTask = $process.StandardOutput.ReadToEndAsync()
        $errTask = $process.StandardError.ReadToEndAsync()
        $process.WaitForExit()

        return [pscustomobject]@{
            ExitCode = $process.ExitCode
            Stdout   = $outTask.GetAwaiter().GetResult()
            Stderr   = $errTask.GetAwaiter().GetResult()
        }
    } finally {
        foreach ($key in $previous.Keys) {
            [Environment]::SetEnvironmentVariable($key, $previous[$key])
        }
    }
}

function New-DrillClone {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([string])]
    param([Parameter(Mandatory)][string] $Identity)

    $dir = Join-Path ([IO.Path]::GetTempPath()) "drill-$Identity-$([guid]::NewGuid().ToString('N').Substring(0,8))"

    # The attribute was added to satisfy the state-changing-verb rule and then
    # never honoured, which the analyzer caught as PSShouldProcess. Declaring
    # support for -WhatIf without implementing it is worse than not declaring
    # it: the switch would be accepted and ignored.
    if (-not $PSCmdlet.ShouldProcess($repositoryUrl, "clone as $Identity")) {
        return ''
    }

    $clone = Invoke-Git -Identity $Identity -Arguments @('clone', $repositoryUrl, $dir)
    if ($clone.ExitCode -ne 0) {
        throw "Could not clone as '$Identity': $($clone.Stderr). Every guard for this identity would otherwise report AuthFailure."
    }

    foreach ($config in @(@('user.email', "$Identity@guard-drill.invalid"), @('user.name', "guard-drill-$Identity"))) {
        $null = Invoke-Git -Identity $Identity -WorkingDirectory $dir -Arguments @('config', $config[0], $config[1])
    }
    return $dir
}

function Set-DrillFileContent {
    <#
        .SYNOPSIS
        Changes the drill token in the working tree, and proves it changed.

        .DESCRIPTION
        Asserting the change is not defensive padding. On the first live run
        this wrote nothing, every commit was therefore empty, and every push
        was a no-op that exited zero -- which the classifier read as the push
        succeeding. Four guards reported that a protected branch had let a push
        through while main sat untouched.

        So an edit that does not alter the file is a failure here, at the point
        where the cause is visible, rather than a confident wrong answer six
        steps later.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string] $Directory,
        [Parameter(Mandatory)][string] $Text
    )
    $path = Join-Path $Directory 'README.md'
    if (-not $PSCmdlet.ShouldProcess($path, 'write drill token')) { return }

    if (-not (Test-Path -LiteralPath $path)) {
        throw "No README.md in '$Directory'. The clone did not produce the seeded file, so there is nothing for a pull request to modify."
    }

    $existing = [System.IO.File]::ReadAllText($path)
    if ($existing -notmatch 'drill-token:') {
        throw "README.md in '$Directory' has no 'drill-token:' line to change. Terraform seeds one; without it every commit is empty and every push a no-op that exits zero."
    }

    $updated = $existing -replace 'drill-token: .*', "drill-token: $Text"
    [System.IO.File]::WriteAllText($path, $updated, (New-Object System.Text.UTF8Encoding($false)))

    $after = [System.IO.File]::ReadAllText($path)
    if ($after -eq $existing) {
        throw "Writing the drill token to '$path' changed nothing. The commit would be empty and the push a no-op reported as success."
    }
}

function Invoke-DrillCommit {
    <#
        .SYNOPSIS
        Commits the working tree and refuses to continue if nothing was committed.

        .DESCRIPTION
        "git commit -am" exits non-zero when there is nothing to commit, and the
        first live run discarded that result with $null =. The push that followed
        had nothing to send, printed "Everything up-to-date", exited zero, and
        was graded as the branch policy having failed.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string] $Identity,
        [Parameter(Mandatory)][string] $Directory,
        [Parameter(Mandatory)][string] $Message
    )
    if (-not $PSCmdlet.ShouldProcess($Directory, "commit as $Identity")) { return }

    $before = (Invoke-Git -Identity $Identity -WorkingDirectory $Directory -Arguments @('rev-parse', 'HEAD')).Stdout.Trim()
    $commit = Invoke-Git -Identity $Identity -WorkingDirectory $Directory -Arguments @('commit', '-am', $Message)
    $after = (Invoke-Git -Identity $Identity -WorkingDirectory $Directory -Arguments @('rev-parse', 'HEAD')).Stdout.Trim()

    if ($commit.ExitCode -ne 0 -or $after -eq $before) {
        throw ("Commit as '$Identity' produced nothing (exit $($commit.ExitCode)). " +
            "Every push after this would be a no-op that exits zero and reads as a control letting it through. " +
            "git said: $($commit.Stdout.Trim()) $($commit.Stderr.Trim())")
    }
}

# ------------------------------------------------------------------ guards

$observations = @{}

function Set-Observation {
    [CmdletBinding(SupportsShouldProcess)]
    param(
        [Parameter(Mandatory)][string] $Id,
        [Parameter(Mandatory)][string] $Outcome,
        [Parameter(Mandatory)][string] $Reason
    )
    if ($PSCmdlet.ShouldProcess($Id, 'record observation')) {
        $observations[$Id] = [pscustomobject]@{ Outcome = $Outcome; Reason = $Reason }
        Write-Information ("  {0,-42} {1}" -f $Id, $Outcome)
    }
}

Write-Information "`n== git guards"

$authorClone = New-DrillClone -Identity 'author'

# push-to-protected-branch
Set-DrillFileContent -Directory $authorClone -Text "direct-push-$(Get-Random)"
Invoke-DrillCommit -Identity 'author' -Directory $authorClone -Message 'Attempt a direct push to a protected branch'
$push = Invoke-Git -Identity 'author' -WorkingDirectory $authorClone -Arguments @('push', 'origin', $branchShort)
$verdict = Resolve-PushOutcome -ExitCode $push.ExitCode -Stderr $push.Stderr -Stdout $push.Stdout
Set-Observation -Id 'push-to-protected-branch' -Outcome $verdict.Outcome -Reason $verdict.Reason

# force-push-to-protected-branch
$forcePush = Invoke-Git -Identity 'author' -WorkingDirectory $authorClone -Arguments @('push', '--force', 'origin', $branchShort)
$verdict = Resolve-PushOutcome -ExitCode $forcePush.ExitCode -Stderr $forcePush.Stderr -Stdout $forcePush.Stdout
Set-Observation -Id 'force-push-to-protected-branch' -Outcome $verdict.Outcome -Reason $verdict.Reason

# delete-protected-branch
$deleteBranch = Invoke-Git -Identity 'author' -WorkingDirectory $authorClone -Arguments @('push', 'origin', '--delete', $branchShort)
$verdict = Resolve-PushOutcome -ExitCode $deleteBranch.ExitCode -Stderr $deleteBranch.Stderr -Stdout $deleteBranch.Stdout
Set-Observation -Id 'delete-protected-branch' -Outcome $verdict.Outcome -Reason $verdict.Reason

# policy-exempt-push. Runs last of the git guards on purpose: it is expected to
# SUCCEED, which moves main, and any guard reading main afterwards would be
# reading a branch this guard changed.
$exemptClone = New-DrillClone -Identity 'exempt'
Set-DrillFileContent -Directory $exemptClone -Text "exempt-push-$(Get-Random)"
Invoke-DrillCommit -Identity 'exempt' -Directory $exemptClone -Message 'Push to a protected branch while holding PolicyExempt'
$exemptPush = Invoke-Git -Identity 'exempt' -WorkingDirectory $exemptClone -Arguments @('push', 'origin', $branchShort)
$verdict = Resolve-PushOutcome -ExitCode $exemptPush.ExitCode -Stderr $exemptPush.Stderr -Stdout $exemptPush.Stdout
Set-Observation -Id 'policy-exempt-push' -Outcome $verdict.Outcome -Reason $verdict.Reason

Write-Information "`n== pull request guards"

$identityIds = @{}
foreach ($name in @('author', 'reviewer', 'dissenter')) {
    $identityIds[$name] = Get-AdoIdentityId -Identity $name
}

function New-DrillPullRequest {
    <#
        .SYNOPSIS
        Pushes a branch as the author and opens a pull request into main.
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][string] $Label)

    $branch = "drill/$Label-$([guid]::NewGuid().ToString('N').Substring(0,6))"
    $dir = New-DrillClone -Identity 'author'

    $null = Invoke-Git -Identity 'author' -WorkingDirectory $dir -Arguments @('checkout', '-b', $branch)
    Set-DrillFileContent -Directory $dir -Text "$Label-initial"
    Invoke-DrillCommit -Identity 'author' -Directory $dir -Message "Change for $Label"
    $push = Invoke-Git -Identity 'author' -WorkingDirectory $dir -Arguments @('push', '-u', 'origin', $branch)
    if ($push.ExitCode -ne 0) {
        # A topic branch is not protected, so this must work. If it does not,
        # the pull request guards have no subject and reporting them as
        # refusals would credit a policy for a broken push.
        throw "Could not push topic branch '$branch': $($push.Stderr)"
    }

    $create = Invoke-Ado -Identity 'author' -Method Post `
        -Uri "$organization/$projectName/_apis/git/repositories/$repositoryId/pullrequests?api-version=$script:ApiVersion" `
        -Body @{
        sourceRefName = "refs/heads/$branch"
        targetRefName = $defaultBranch
        title         = "Guard drill: $Label"
        description   = 'Opened by the pipelines-that-refuse drill. Destroyed with the project.'
    }
    if ($create.StatusCode -lt 200 -or $create.StatusCode -ge 300) {
        throw "Could not open a pull request for '$Label': HTTP $($create.StatusCode) $($create.Raw)"
    }

    return [pscustomobject]@{
        Id        = $create.Body.pullRequestId
        Branch    = $branch
        Directory = $dir
    }
}

function Set-DrillVote {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([int])]
    param(
        [Parameter(Mandatory)][string] $Identity,
        [Parameter(Mandatory)][int] $PullRequestId,
        # 10 approve, 5 approve with suggestions, 0 no vote, -5 waiting, -10 reject
        [Parameter(Mandatory)][int] $Vote
    )
    if (-not $PSCmdlet.ShouldProcess("PR $PullRequestId", "vote $Vote as $Identity")) { return 0 }

    $id = $identityIds[$Identity]
    $result = Invoke-Ado -Identity $Identity -Method Put `
        -Uri "$organization/$projectName/_apis/git/repositories/$repositoryId/pullrequests/$PullRequestId/reviewers/$id`?api-version=$script:ApiVersion" `
        -Body @{ vote = $Vote; id = $id }
    return [int]$result.StatusCode
}

function Test-DrillCompletion {
    <#
        .SYNOPSIS
        Asks the API to complete a pull request and reports what happened.

        .DESCRIPTION
        Completion is asynchronous. A 200 means the request was accepted, not
        that the merge occurred, so the pull request is read back and the
        classification is made from its resulting status. Trusting the status
        code alone would report a bypass that never happened.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param([Parameter(Mandatory)][int] $PullRequestId)

    $current = Invoke-Ado -Identity 'author' `
        -Uri "$organization/$projectName/_apis/git/repositories/$repositoryId/pullrequests/$PullRequestId`?api-version=$script:ApiVersion"
    if ($current.StatusCode -ne 200) {
        return Resolve-PullRequestOutcome -StatusCode $current.StatusCode -Body $current.Raw
    }

    $attempt = Invoke-Ado -Identity 'author' -Method Patch `
        -Uri "$organization/$projectName/_apis/git/repositories/$repositoryId/pullrequests/$PullRequestId`?api-version=$script:ApiVersion" `
        -Body @{
        status                = 'completed'
        lastMergeSourceCommit = @{ commitId = $current.Body.lastMergeSourceCommit.commitId }
        completionOptions     = @{ deleteSourceBranch = $false; mergeStrategy = 'noFastForward' }
    }

    # Azure DevOps queues the merge, so the status immediately after the PATCH
    # is not the answer. Poll briefly for a terminal state.
    $status = ''
    foreach ($i in 1..15) {
        Start-Sleep -Seconds 2
        $after = Invoke-Ado -Identity 'author' `
            -Uri "$organization/$projectName/_apis/git/repositories/$repositoryId/pullrequests/$PullRequestId`?api-version=$script:ApiVersion"
        if ($after.StatusCode -eq 200) {
            $status = [string]$after.Body.status
            if ($status -eq 'completed') { break }
            $mergeStatus = if ($after.Body.PSObject.Properties.Name -contains 'mergeStatus') { [string]$after.Body.mergeStatus } else { '' }
            if ($mergeStatus -eq 'rejectedByPolicy') { break }
        }
    }

    return Resolve-PullRequestOutcome -StatusCode $attempt.StatusCode -Body $attempt.Raw -ResultingStatus $status
}

# complete-pr-without-approval
$pr = New-DrillPullRequest -Label 'no-approval'
$verdict = Test-DrillCompletion -PullRequestId $pr.Id
Set-Observation -Id 'complete-pr-without-approval' -Outcome $verdict.Outcome -Reason $verdict.Reason

# self-approve-own-pr
$pr = New-DrillPullRequest -Label 'self-approve'
$voteStatus = Set-DrillVote -Identity 'author' -PullRequestId $pr.Id -Vote 10
$verdict = Test-DrillCompletion -PullRequestId $pr.Id
Set-Observation -Id 'self-approve-own-pr' -Outcome $verdict.Outcome `
    -Reason "$($verdict.Reason) The author's own approve vote returned HTTP $voteStatus."

# stale-approval-survives-new-commit
$pr = New-DrillPullRequest -Label 'stale-approval'
$null = Set-DrillVote -Identity 'reviewer' -PullRequestId $pr.Id -Vote 10
# The approval now exists for this diff. Change the diff underneath it.
Set-DrillFileContent -Directory $pr.Directory -Text "stale-approval-changed-$(Get-Random)"
Invoke-DrillCommit -Identity 'author' -Directory $pr.Directory -Message 'Change the code after it was approved'
$pushAfter = Invoke-Git -Identity 'author' -WorkingDirectory $pr.Directory -Arguments @('push', 'origin', $pr.Branch)
if ($pushAfter.ExitCode -ne 0) {
    Set-Observation -Id 'stale-approval-survives-new-commit' -Outcome 'Unknown' `
        -Reason "Could not push the post-approval commit, so there was no stale approval to test: $($pushAfter.Stderr)"
} else {
    $verdict = Test-DrillCompletion -PullRequestId $pr.Id
    Set-Observation -Id 'stale-approval-survives-new-commit' -Outcome $verdict.Outcome -Reason $verdict.Reason
}

# complete-over-outstanding-rejection
$pr = New-DrillPullRequest -Label 'outstanding-rejection'
$null = Set-DrillVote -Identity 'reviewer' -PullRequestId $pr.Id -Vote 10
$rejectStatus = Set-DrillVote -Identity 'dissenter' -PullRequestId $pr.Id -Vote -10
if ($rejectStatus -lt 200 -or $rejectStatus -ge 300) {
    Set-Observation -Id 'complete-over-outstanding-rejection' -Outcome 'Unknown' `
        -Reason "The dissenting vote was not recorded (HTTP $rejectStatus), so there was no rejection for completion to override."
} else {
    $verdict = Test-DrillCompletion -PullRequestId $pr.Id
    Set-Observation -Id 'complete-over-outstanding-rejection' -Outcome $verdict.Outcome -Reason $verdict.Reason
}

Write-Information "`n== pipeline guards"

function Start-DrillPipeline {
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([int])]
    param([Parameter(Mandatory)][int] $DefinitionId)

    if (-not $PSCmdlet.ShouldProcess("definition $DefinitionId", 'queue a run')) { return 0 }

    $run = Invoke-Ado -Identity 'author' -Method Post `
        -Uri "$organization/$projectName/_apis/pipelines/$DefinitionId/runs?api-version=$script:ApiVersion" `
        -Body @{ }
    if ($run.StatusCode -lt 200 -or $run.StatusCode -ge 300) {
        throw "Could not queue definition $DefinitionId : HTTP $($run.StatusCode) $($run.Raw)"
    }
    return [int]$run.Body.id
}

function Wait-DrillRun {
    <#
        .SYNOPSIS
        Waits until a run has either finished or stalled at a checkpoint.

        .DESCRIPTION
        Returns whatever it last saw rather than throwing on timeout, because
        "still running after ten minutes" is itself an observation the caller
        has to classify -- and a timeout silently treated as a block would be
        the exact false pass this lab is about.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)][int] $BuildId,

        # Passed in rather than read from the caller's scope. Relying on scope
        # capture worked and was invisible to static analysis, which is a poor
        # trade for one argument.
        [Parameter(Mandatory)][int] $TimeoutSeconds,

        [Parameter()][switch] $StopAtCheckpoint
    )

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $build = $null
    $timeline = $null

    while ((Get-Date) -lt $deadline) {
        $build = Invoke-Ado -Identity 'author' -Uri "$organization/$projectName/_apis/build/builds/$BuildId`?api-version=$script:ApiVersion"
        $timeline = Invoke-Ado -Identity 'author' -Uri "$organization/$projectName/_apis/build/builds/$BuildId/timeline?api-version=$script:ApiVersion"

        if ($build.StatusCode -eq 200 -and [string]$build.Body.status -eq 'completed') { break }

        if ($StopAtCheckpoint -and $timeline.StatusCode -eq 200 -and $null -ne $timeline.Body.records) {
            $checkpoint = @($timeline.Body.records | Where-Object {
                    $_.type -like 'Checkpoint*' -and [string]$_.state -ne 'completed'
                })
            if ($checkpoint.Count) { break }
        }
        Start-Sleep -Seconds 10
    }

    return [pscustomobject]@{
        Build    = $build
        Timeline = $timeline
        TimedOut = (Get-Date) -ge $deadline
    }
}

# deploy-without-environment-approval
$deployBuildId = Start-DrillPipeline -DefinitionId ([int]$pipelineIds.gated_deploy)
$deployState = Wait-DrillRun -BuildId $deployBuildId -TimeoutSeconds $PipelineTimeoutSeconds -StopAtCheckpoint

$records = if ($deployState.Timeline.StatusCode -eq 200 -and $null -ne $deployState.Timeline.Body.records) {
    @($deployState.Timeline.Body.records)
} else { @() }

# The load-bearing reading: did the deployment job execute? Taken from the job
# record rather than the run's overall state, because a pipeline that failed to
# compile also never deployed.
$deployJob = @($records | Where-Object { $_.type -eq 'Job' -and $_.name -like '*Deploy*' })
$buildJob = @($records | Where-Object { $_.type -eq 'Job' -and $_.name -like '*Build*' })
$deploymentExecuted = [bool](@($deployJob | Where-Object { [string]$_.state -ne 'pending' -and [string]$_.result -ne 'skipped' }).Count)
$approvalPending = [bool](@($records | Where-Object { $_.type -like 'Checkpoint*' -and [string]$_.state -ne 'completed' }).Count)

if (-not $buildJob.Count -or @($buildJob | Where-Object { [string]$_.result -eq 'failed' }).Count) {
    # The build stage exists so this case is separable. Without it, a pipeline
    # that never compiled would look exactly like an approval holding the line.
    Set-Observation -Id 'deploy-without-environment-approval' -Outcome 'Unknown' `
        -Reason 'The build stage did not succeed, so the deployment stage was never reached and nothing can be concluded about the approval check.'
} else {
    $verdict = Resolve-ApprovalOutcome -RunState ([string]$deployState.Build.Body.status) `
        -ApprovalPending $approvalPending -DeploymentExecuted $deploymentExecuted
    Set-Observation -Id 'deploy-without-environment-approval' -Outcome $verdict.Outcome -Reason $verdict.Reason
}

function Get-DrillRunLog {
    [CmdletBinding()]
    [OutputType([string])]
    param([Parameter(Mandatory)][int] $BuildId)

    $logs = Invoke-Ado -Identity 'author' -Uri "$organization/$projectName/_apis/build/builds/$BuildId/logs?api-version=$script:ApiVersion"
    if ($logs.StatusCode -ne 200 -or $null -eq $logs.Body.value) { return '' }

    $text = New-Object System.Text.StringBuilder
    foreach ($log in @($logs.Body.value)) {
        $one = Invoke-Ado -Identity 'author' -Uri "$organization/$projectName/_apis/build/builds/$BuildId/logs/$($log.id)?api-version=$script:ApiVersion"
        if ($one.StatusCode -eq 200) {
            $null = $text.AppendLine(($one.Body | Out-String))
        }
    }
    return $text.ToString()
}

foreach ($case in @(
        @{ Id = 'secret-masked-in-log'; Definition = [int]$pipelineIds.secret_masked; Marker = 'SECRET_STEP_RAN' }
        @{ Id = 'secret-masking-defeated-by-transform'; Definition = [int]$pipelineIds.secret_transformed; Marker = 'TRANSFORM_STEP_RAN' }
    )) {
    $buildId = Start-DrillPipeline -DefinitionId $case.Definition
    $null = Wait-DrillRun -BuildId $buildId -TimeoutSeconds $PipelineTimeoutSeconds
    $log = Get-DrillRunLog -BuildId $buildId
    $verdict = Resolve-SecretExposure -Log $log -Secret $drillSecret -Marker $case.Marker
    Set-Observation -Id $case.Id -Outcome $verdict.Outcome -Reason $verdict.Reason
}

# ------------------------------------------------------------------ grading

Write-Information "`n== grading against guard-matrix.json"

$matrix = Get-GuardMatrix -Path $MatrixPath
$passColumn = if ($Pass -eq 'hardened') { 'Hardened' } else { 'Default' }

$results = @()
foreach ($guard in $matrix.guards) {
    if (-not $observations.ContainsKey($guard.id)) {
        # A guard the drill never attempted is not a pass. Recording it as
        # Unknown makes the omission visible in the report instead of shrinking
        # the denominator.
        $results += Test-GuardExpectation -Guard $guard -Pass $passColumn -Observed 'Unknown' `
            -Reason 'The drill did not attempt this guard. A guard that did not run cannot have held.'
        continue
    }
    $observed = $observations[$guard.id]
    $results += Test-GuardExpectation -Guard $guard -Pass $passColumn -Observed $observed.Outcome -Reason $observed.Reason
}

$report = Get-GuardReport -Result $results

$payload = [pscustomobject]@{
    generatedUtc   = (Get-Date).ToUniversalTime().ToString('o')
    organization   = $organization
    project        = $projectName
    pass           = $Pass
    policyApplied  = $appliedPolicy
    environment    = $environmentName
    exemptGroup    = (Get-TfValue 'policy_exempt_group')
    total          = $report.Total
    passed         = $report.Passed
    failed         = $report.Failed
    inconclusive   = $report.Inconclusive
    findings       = $report.Findings
    ok             = $report.Ok
    results        = $results
}
[System.IO.File]::WriteAllText($ReportPath, ($payload | ConvertTo-Json -Depth 8), (New-Object System.Text.UTF8Encoding($false)))

$lines = @(
    "# Guard drill - $Pass pass"
    ''
    "$($report.Passed)/$($report.Total) guards behaved as declared. $($report.Failed) failed, $($report.Inconclusive) inconclusive, $($report.Findings) findings configuration cannot close."
    ''
    '| Guard | Identity | Expected | Observed | |'
    '|---|---|---|---|---|'
)
foreach ($r in $results) {
    $mark = if ($r.Inconclusive) { 'inconclusive' } elseif ($r.Passed) { 'as declared' } else { 'FAILED' }
    $lines += "| ``$($r.Id)`` | $($r.Surface) | $($r.Expected) | $($r.Observed) | $mark |"
}
$lines += @(
    ''
    '## Why the exemption is not closed'
    ''
    "Branch policies on this repository are overridden by anyone holding ``PolicyExempt``. In this run that is the group **$((Get-TfValue 'policy_exempt_group').name)**. No policy setting closes it; only membership does."
)
[System.IO.File]::WriteAllText($MarkdownPath, ($lines -join "`n"), (New-Object System.Text.UTF8Encoding($false)))

Write-Information ''
Write-Information "$($report.Passed)/$($report.Total) as declared; $($report.Failed) failed; $($report.Inconclusive) inconclusive."
foreach ($r in @($results | Where-Object { -not $_.Passed })) {
    Write-Information "FAILED  $($r.Id): expected $($r.Expected), observed $($r.Observed). $($r.Reason)"
}

if (-not $report.Ok) {
    throw "The drill did not hold: $($report.Failed) of $($report.Total) guards did not behave as declared."
}
Write-Information 'Every guard behaved as declared.'
