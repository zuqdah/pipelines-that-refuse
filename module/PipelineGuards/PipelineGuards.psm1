#Requires -Version 7.0

<#
    PipelineGuards

    The judgement half of the lab, kept free of any call to Azure DevOps so that
    every decision about what an observation means can be tested without an
    organization, a project, or a pipeline run.

    The whole module exists because of one distinction: "the push was refused"
    is not a result. A push refused by a branch policy and a push refused by a
    failed login produce the same non-zero exit code, and only one of them says
    anything about the control. Three separate labs in this series have now been
    caught reporting success from an operation that never ran, so refusal is
    classified by cause here, and a cause that cannot be identified is a
    failure rather than a pass.
#>

Set-StrictMode -Version Latest

# Outcomes a guard can observe. Kept as a list rather than an enum so the JSON
# matrix and this module cannot drift apart silently -- Get-GuardMatrix checks
# every declared expectation against it.
$script:KnownOutcomes = @(
    'Allowed'
    'RefusedByPolicy'
    'RefusedByPermission'
    'AuthFailure'
    'Blocked'
    'Masked'
    'Leaked'
    'Unknown'
)

function Get-KnownGuardOutcome {
    <#
        .SYNOPSIS
        The outcomes a drill is allowed to report.
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    # Cast rather than @(): the declared OutputType is string[] and returning a
    # bare Object[] makes that declaration a lie the analyzer correctly objects to.
    return [string[]]$script:KnownOutcomes
}

function Get-GuardMatrix {
    <#
        .SYNOPSIS
        Loads guard-matrix.json and refuses to return an incoherent one.

        .DESCRIPTION
        A matrix that declares nothing testable makes the drill unfalsifiable,
        which is worse than having no matrix at all because the report still
        looks rigorous. Everything that would make the results meaningless is
        checked here and throws.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [string] $Path
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Guard matrix not found at '$Path'."
    }

    # Not Get-Content -Raw: it returns a string carrying ETS note properties
    # whose object graph makes ConvertFrom-Json/ConvertTo-Json hang.
    $text = [System.IO.File]::ReadAllText($Path)
    if ([string]::IsNullOrWhiteSpace($text)) {
        throw "Guard matrix at '$Path' is empty."
    }

    $matrix = $text | ConvertFrom-Json

    $guards = @($matrix.guards)
    if (-not $guards.Count) {
        throw 'The guard matrix declares no guards.'
    }

    $ids = @{}
    foreach ($guard in $guards) {
        foreach ($field in 'id', 'title', 'surface', 'expectDefault', 'expectHardened', 'severity', 'why') {
            # -contains, not .Contains(): the property-name collection on a
            # PSCustomObject from ConvertFrom-Json does not reliably expose the
            # method, and under StrictMode that is a terminating error rather
            # than the false this reads like.
            if (-not ($guard.PSObject.Properties.Name -contains $field) -or
                [string]::IsNullOrWhiteSpace([string]$guard.$field)) {
                throw "Guard '$($guard.id)' is missing '$field'. Every guard must state what it expects and why."
            }
        }

        if ($ids.ContainsKey($guard.id)) {
            throw "Guard id '$($guard.id)' is declared more than once."
        }
        $ids[$guard.id] = $true

        foreach ($field in 'expectDefault', 'expectHardened') {
            if ($guard.$field -notin $script:KnownOutcomes) {
                throw "Guard '$($guard.id)' expects '$($guard.$field)' for $field, which is not a known outcome."
            }
        }

        # A guard that expects Unknown is asking to be told nothing.
        if ($guard.expectDefault -eq 'Unknown' -or $guard.expectHardened -eq 'Unknown') {
            throw "Guard '$($guard.id)' expects 'Unknown', which no guard may expect."
        }
    }

    # The matrix has to contain a control that is expected to hold and one that
    # is expected not to. Without the first there is nothing being verified;
    # without the second, a drill that reported refusal for everything -- which
    # is what a broken login looks like -- would pass every guard.
    $expectedToHold = @($guards | Where-Object {
            $_.expectHardened -in 'RefusedByPolicy', 'RefusedByPermission', 'Blocked', 'Masked'
        })
    $expectedToGiveWay = @($guards | Where-Object { $_.expectHardened -in 'Allowed', 'Leaked' })

    if (-not $expectedToHold.Count) {
        throw 'No guard expects a control to hold, so the drill verifies nothing.'
    }
    if (-not $expectedToGiveWay.Count) {
        throw 'No guard expects a control to give way. A drill where every refusal is a pass cannot tell a working policy from a broken connection.'
    }

    # The two-pass design only proves something if hardening changes an outcome.
    # With no divergence the second pass is an expensive way to get the same
    # answer twice, and the report would claim a remediation boundary it never
    # crossed.
    $diverging = @($guards | Where-Object { $_.expectDefault -ne $_.expectHardened })
    if (-not $diverging.Count) {
        throw 'No guard expects a different outcome after hardening, so the hardened pass demonstrates no remediation boundary.'
    }

    # Cross-check only when the matrix declares identities. If it does, a guard
    # naming one that does not exist is a typo that would send the drill to the
    # wrong credential and report the wrong thing confidently.
    $declared = @()
    if ($matrix.PSObject.Properties.Name -contains 'identities') {
        $declared = @($matrix.identities.PSObject.Properties.Name)
    }
    if ($declared.Count) {
        foreach ($guard in $guards) {
            if (-not ($guard.PSObject.Properties.Name -contains 'identity')) {
                throw "Guard '$($guard.id)' names no identity, but the matrix declares $($declared.Count)."
            }
            if ($guard.identity -notin $declared) {
                throw "Guard '$($guard.id)' runs as identity '$($guard.identity)', which the matrix does not declare."
            }
        }
    }

    return $matrix
}

function Resolve-PushOutcome {
    <#
        .SYNOPSIS
        Works out why a git push failed, not merely that it did.

        .DESCRIPTION
        Order matters here. Authentication is checked first and deliberately,
        because a push that never reached the server is the case most likely to
        be mistaken for a policy that worked: exit code non-zero, stderr full of
        refusal, and nothing whatsoever proven.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [int] $ExitCode,

        [Parameter()]
        [AllowEmptyString()]
        [string] $Stderr = '',

        # git reports "Everything up-to-date" on stderr, but which stream
        # carries what varies by version, so both are scanned together.
        [Parameter()]
        [AllowEmptyString()]
        [string] $Stdout = ''
    )

    $text = ($Stderr + "`n" + $Stdout)

    # Checked before the exit code, and the reason is the whole point of this
    # module. A push with nothing to send prints "Everything up-to-date" and
    # exits ZERO. Reading that as Allowed reports a control that failed, when
    # in fact nothing was ever attempted -- the same mistake as counting a
    # failed login as a policy refusal, in the opposite direction.
    #
    # The first live run of this lab reported four guards as Allowed this way.
    # main was untouched, the commit had silently failed, and every push was a
    # no-op that exited 0.
    if ($text -match 'Everything up-to-date') {
        return [pscustomobject]@{
            Outcome = 'Unknown'
            Reason  = 'git reported "Everything up-to-date", so nothing was pushed. Whether the branch would have refused a real push is untested, and reporting this as Allowed would claim a control failed against an operation that never happened.'
            Signal  = 'nothing to push'
        }
    }

    # Checked before anything else: these mean the push never reached a policy.
    $authPatterns = @(
        'Authentication failed'
        'could not read Username'
        'TF400813'                      # user is not authorized to access this resource
        'TF401019'                      # repository does not exist or you lack access
        'fatal: repository .* not found'
        'HTTP (401|403)'
        'Invalid username or password'
        'terminal prompts disabled'
    )
    foreach ($pattern in $authPatterns) {
        if ($text -match $pattern) {
            return [pscustomobject]@{
                Outcome = 'AuthFailure'
                Reason  = "Refused before any policy was consulted (matched '$pattern')."
                Signal  = $pattern
            }
        }
    }

    if ($ExitCode -eq 0) {
        return [pscustomobject]@{
            Outcome = 'Allowed'
            Reason  = 'The push completed.'
            Signal  = 'exit 0'
        }
    }

    # Branch policy refusals. TF402455 is the one a protected branch produces.
    $policyPatterns = @(
        'TF402455'                      # pushes to this branch are not permitted; use a pull request
        'VS402337'
        'rejected because.*branch polic'
        'not permitted.*pull request'
        'branch policies'
    )
    foreach ($pattern in $policyPatterns) {
        if ($text -match $pattern) {
            return [pscustomobject]@{
                Outcome = 'RefusedByPolicy'
                Reason  = "A branch policy refused the push (matched '$pattern')."
                Signal  = $pattern
            }
        }
    }

    # Permission refusals are a different subsystem from branch policies, and
    # conflating them would let a lab claim its policy work covered force
    # pushes when the access control entry is what actually stopped them.
    $permissionPatterns = @(
        'TF401027'                      # you need the Git 'ForcePush' permission
        "You need the Git '"
        'denied.*permission'
        'permission.*denied'
    )
    foreach ($pattern in $permissionPatterns) {
        if ($text -match $pattern) {
            return [pscustomobject]@{
                Outcome = 'RefusedByPermission'
                Reason  = "An access control entry refused the push (matched '$pattern')."
                Signal  = $pattern
            }
        }
    }

    return [pscustomobject]@{
        Outcome = 'Unknown'
        Reason  = "Push failed with exit code $ExitCode and stderr that matched no known cause. Treated as a failure: an unexplained refusal is not evidence a control worked."
        Signal  = ''
    }
}

function Resolve-PullRequestOutcome {
    <#
        .SYNOPSIS
        Classifies an attempt to complete a pull request through the REST API.

        .DESCRIPTION
        The API is the right surface to test. The web UI disables the complete
        button when policies are unmet, which proves the button is disabled and
        nothing else; the API will accept the request and let the server decide.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [int] $StatusCode,

        [Parameter()]
        [AllowEmptyString()]
        [string] $Body = '',

        # The merge status the PR reports after the attempt. A 200 on the
        # completion call does not mean the merge happened -- Azure DevOps
        # queues it and reports the outcome on the pull request itself.
        [Parameter()]
        [AllowEmptyString()]
        [string] $ResultingStatus = '',

        # What the policy evaluations API says about this pull request, which is
        # the only authoritative answer available.
        #
        # Status codes are not enough. A completion refused because a blocking
        # policy is unmet and the caller holds no bypass comes back 403, which
        # is indistinguishable by code alone from a caller with no access at
        # all. The first version read 403 as AuthFailure -- safe, because it
        # proves nothing, but it under-reported a policy that was working
        # exactly as intended. Asking the service which policies are unmet
        # removes the guess rather than replacing it with a better one.
        [Parameter()]
        [ValidateSet('Unmet', 'Met', 'Unknown')]
        [string] $BlockingPolicies = 'Unknown'
    )

    # Checked first: a completed pull request is a bypass whatever else is true.
    if ($ResultingStatus -eq 'completed') {
        return [pscustomobject]@{
            Outcome = 'Allowed'
            Reason  = 'The pull request completed.'
            Signal  = 'status=completed'
        }
    }

    # Authoritative, so it outranks the status code. The pull request did not
    # complete and the service reports a blocking policy unsatisfied: that is
    # the policy holding, whatever HTTP code the completion call returned.
    if ($BlockingPolicies -eq 'Unmet') {
        return [pscustomobject]@{
            Outcome = 'RefusedByPolicy'
            Reason  = "The pull request did not complete and the policy evaluations report a blocking policy unmet (completion returned HTTP $StatusCode)."
            Signal  = 'evaluations: blocking policy unmet'
        }
    }

    if ($StatusCode -eq 401) {
        return [pscustomobject]@{
            Outcome = 'AuthFailure'
            Reason  = 'HTTP 401. The request was rejected before policy evaluation.'
            Signal  = 'HTTP 401'
        }
    }

    if ($StatusCode -eq 403) {
        # Reached only when the evaluations could not be read or reported every
        # blocking policy satisfied. Then a 403 really is an access problem, and
        # calling it one is the safe direction: it proves nothing about the
        # control either way.
        return [pscustomobject]@{
            Outcome = 'AuthFailure'
            Reason  = "HTTP 403 with blocking policies reported '$BlockingPolicies'. Without an unmet policy to attribute it to, this is an access failure and proves nothing about the control."
            Signal  = 'HTTP 403'
        }
    }

    if ($Body -match 'PolicyConfiguration|policy is not met|blocking polic|MinimumApproverCount|TF402484') {
        return [pscustomobject]@{
            Outcome = 'RefusedByPolicy'
            Reason  = 'The service refused completion because a blocking policy was unmet.'
            Signal  = 'policy error in response body'
        }
    }

    if ($StatusCode -ge 200 -and $StatusCode -lt 300) {
        # This is the trap. Completion is asynchronous: a 200 means the request
        # was accepted, and the pull request can still sit at 'active' because a
        # policy refused the merge. Believing the status code alone would report
        # a bypass that never happened. The 'completed' case is handled at the
        # top of the function, before anything else.
        if ($ResultingStatus -in 'active', 'notSet', 'queued') {
            return [pscustomobject]@{
                Outcome = 'RefusedByPolicy'
                Reason  = "Completion was accepted (HTTP $StatusCode) but the pull request remains '$ResultingStatus', so the merge did not happen."
                Signal  = "status=$ResultingStatus"
            }
        }

        return [pscustomobject]@{
            Outcome = 'Unknown'
            Reason  = "HTTP $StatusCode with resulting status '$ResultingStatus'. Accepting this as either outcome would be a guess."
            Signal  = "status=$ResultingStatus"
        }
    }

    # The body is included rather than summarised away. An earlier run reported
    # "HTTP 409 with no recognised policy error" four times running, which is
    # correct and useless: refusing to guess is right, but a verdict that
    # cannot be investigated wastes the run that produced it.
    $excerpt = if ([string]::IsNullOrWhiteSpace($Body)) { '(empty body)' } else { $Body.Substring(0, [Math]::Min(400, $Body.Length)) }

    return [pscustomobject]@{
        Outcome = 'Unknown'
        Reason  = "HTTP $StatusCode with blocking policies '$BlockingPolicies' and no recognised policy error. Unexplained, therefore a failure. The service said: $excerpt"
        Signal  = "HTTP $StatusCode"
    }
}

function Resolve-ApprovalOutcome {
    <#
        .SYNOPSIS
        Decides whether a deployment actually stopped at an approval.

        .DESCRIPTION
        An approval request appearing is not the control working. The question
        is whether the deployment job ran, and the only honest answer comes from
        the job's own record rather than from the run's overall state.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        # The run's state: inProgress, completed, cancelling, postponed...
        [Parameter(Mandatory)]
        [string] $RunState,

        # Whether an approval is recorded as pending on the environment.
        [Parameter(Mandatory)]
        [bool] $ApprovalPending,

        # Whether the deployment job itself reached execution. This is the
        # load-bearing input: everything else is context.
        [Parameter(Mandatory)]
        [bool] $DeploymentExecuted
    )

    if ($DeploymentExecuted) {
        return [pscustomobject]@{
            Outcome = 'Allowed'
            Reason  = 'The deployment job executed, so the approval did not gate it.'
            Signal  = 'deployment executed'
        }
    }

    if ($ApprovalPending) {
        return [pscustomobject]@{
            Outcome = 'Blocked'
            Reason  = "The deployment did not execute and an approval is pending (run state '$RunState')."
            Signal  = 'approval pending, deployment not executed'
        }
    }

    # Did not run, and not because anybody was asked. A compile error in the
    # pipeline produces exactly this, and reading it as the gate working would
    # be the same mistake as counting a failed login as a policy refusal.
    return [pscustomobject]@{
        Outcome = 'Unknown'
        Reason  = "The deployment did not execute but no approval is pending (run state '$RunState'). The job may have failed for an unrelated reason, which proves nothing about the check."
        Signal  = 'no approval pending'
    }
}

function Resolve-SecretExposure {
    <#
        .SYNOPSIS
        Looks for a secret in a pipeline log, including in transformed forms.

        .DESCRIPTION
        Masking is a literal string replacement over log output. Anything that
        changes the bytes on their way to the log defeats it, so a check that
        only searches for the plain value will report a clean log while the
        value sits in it base64-encoded.

        The marker is not optional. A log that does not contain it is a log from
        a step that did not run, and reporting 'Masked' for it would be the
        quiet false pass this series keeps finding.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyString()]
        [string] $Log,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Secret,

        # Printed by the step that handles the secret, so its absence is
        # distinguishable from a step that ran and leaked nothing.
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Marker
    )

    if ($Secret.Length -lt 12) {
        # Short secrets make the punctuation-insensitive scan below produce
        # false positives against ordinary log text.
        throw "Refusing to scan for a secret of $($Secret.Length) characters. Use a long random value, or this check reports leaks that are not there."
    }

    if ($Log -notmatch [regex]::Escape($Marker)) {
        return [pscustomobject]@{
            Outcome = 'Unknown'
            Reason  = "The log does not contain the marker '$Marker', so the step that handles the secret did not run. Nothing is proven either way."
            Signal  = 'marker absent'
        }
    }

    $reversedChars = $Secret.ToCharArray()
    [array]::Reverse($reversedChars)

    $transforms = [ordered]@{
        'plain'    = $Secret
        'base64'   = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($Secret))
        'reversed' = -join $reversedChars
        'hex'      = -join ([Text.Encoding]::UTF8.GetBytes($Secret) | ForEach-Object { $_.ToString('x2') })
    }

    foreach ($name in $transforms.Keys) {
        $needle = $transforms[$name]
        if ($Log -match [regex]::Escape($needle)) {
            return [pscustomobject]@{
                Outcome = 'Leaked'
                Reason  = "The secret is in the log in its $name form."
                Signal  = $name
            }
        }
    }

    # Catches separator tricks in one go: printing the value one character per
    # line, space-separated, or hyphenated all survive masking and all collapse
    # to the same thing once punctuation and whitespace are removed. Safe only
    # because the secret is long, which is asserted above.
    $stripped = ($Log -replace '[^A-Za-z0-9]', '')
    $secretStripped = ($Secret -replace '[^A-Za-z0-9]', '')
    if ($secretStripped.Length -ge 12 -and $stripped -match [regex]::Escape($secretStripped)) {
        return [pscustomobject]@{
            Outcome = 'Leaked'
            Reason  = 'The secret is in the log with separators inserted between its characters, which masking does not catch.'
            Signal  = 'separated'
        }
    }

    return [pscustomobject]@{
        Outcome = 'Masked'
        Reason  = 'The step ran and the secret does not appear in the log in any form checked.'
        Signal  = 'marker present, no match'
    }
}

function Test-GuardExpectation {
    <#
        .SYNOPSIS
        Grades one observation against what the matrix said to expect.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [pscustomobject] $Guard,

        [Parameter(Mandatory)]
        [ValidateSet('Default', 'Hardened')]
        [string] $Pass,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string] $Observed,

        [Parameter()]
        [AllowEmptyString()]
        [string] $Reason = ''
    )

    $expected = if ($Pass -eq 'Default') { $Guard.expectDefault } else { $Guard.expectHardened }

    # Stated separately from the comparison because it is the rule the whole
    # module exists to enforce: an unclassifiable observation fails even where
    # the expectation would otherwise have been met by accident.
    $inconclusive = $Observed -eq 'Unknown'
    $passed = (-not $inconclusive) -and ($Observed -eq $expected)

    return [pscustomobject]@{
        Id           = $Guard.id
        Title        = $Guard.title
        Surface      = $Guard.surface
        Severity     = $Guard.severity
        Pass         = $Pass
        Expected     = $expected
        Observed     = $Observed
        Passed       = $passed
        Inconclusive = $inconclusive
        Reason       = $Reason
        Why          = $Guard.why
    }
}

function Get-GuardReport {
    <#
        .SYNOPSIS
        Summarises graded results and says whether the drill as a whole holds.
    #>
    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param(
        [Parameter(Mandatory)]
        [AllowEmptyCollection()]
        [pscustomobject[]] $Result
    )

    $results = @($Result)

    $failed = @($results | Where-Object { -not $_.Passed })
    $inconclusive = @($results | Where-Object { $_.Inconclusive })

    # An empty result set is not a pass. A drill that graded nothing looks
    # identical to one where every guard held.
    $ok = ($results.Count -gt 0) -and ($failed.Count -eq 0)

    $findings = @($results | Where-Object { $_.Severity -eq 'Finding' -and $_.Passed })

    return [pscustomobject]@{
        Total        = $results.Count
        Passed       = @($results | Where-Object { $_.Passed }).Count
        Failed       = $failed.Count
        Inconclusive = $inconclusive.Count
        Findings     = $findings.Count
        Ok           = $ok
        Results      = $results
    }
}

Export-ModuleMember -Function @(
    'Get-KnownGuardOutcome'
    'Get-GuardMatrix'
    'Resolve-PushOutcome'
    'Resolve-PullRequestOutcome'
    'Resolve-ApprovalOutcome'
    'Resolve-SecretExposure'
    'Test-GuardExpectation'
    'Get-GuardReport'
)
