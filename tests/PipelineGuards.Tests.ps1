#Requires -Version 7.0
#Requires -Modules @{ ModuleName = 'Pester'; ModuleVersion = '5.5.0' }

<#
    Every judgement the drill makes is decided here, against fixtures, with no
    Azure DevOps organization in reach. If any of these ever need a live
    project to run, the separation that makes the drill auditable is gone.

    The tests that matter most are the ones asserting a FAILURE: that a failed
    login is not a policy refusal, that an empty result set is not a pass, that
    a log from a step which never ran is not proof a secret was masked.
#>

BeforeAll {
    $script:ModulePath = Join-Path -Path $PSScriptRoot -ChildPath '../module/PipelineGuards/PipelineGuards.psm1'
    Import-Module $script:ModulePath -Force -ErrorAction Stop

    $script:MatrixPath = Join-Path -Path $PSScriptRoot -ChildPath '../guard-matrix.json'

    # Long enough that the punctuation-insensitive scan cannot false-positive,
    # and shaped like something a pipeline would really hold.
    $script:Secret = 'a7f3c9e15b8d04629fa1c7e3b5d80924'
    $script:Marker = 'SECRET_STEP_RAN'

    # A scriptblock in script scope, not a function. Functions declared in a
    # Describe or Context block -- or at file scope -- are defined during
    # Pester's discovery phase and are gone by the time the It blocks run, which
    # surfaces as CommandNotFoundException and looks nothing like a scoping
    # problem. Script-scoped variables survive into the run phase, so the
    # helper travels as one.
    #
    # WriteAllText with an explicit no-BOM encoding: Set-Content -Encoding utf8
    # writes a BOM on Windows PowerShell, and a BOM before the opening brace
    # makes ConvertFrom-Json fail at position 0.
    $script:WriteMatrix = {
        param([string] $Path, [string] $Json)
        [System.IO.File]::WriteAllText($Path, $Json, (New-Object System.Text.UTF8Encoding($false)))
    }
}

Describe 'Get-GuardMatrix' {

    It 'loads the real matrix shipped with the lab' {
        $matrix = Get-GuardMatrix -Path $script:MatrixPath
        @($matrix.guards).Count | Should -BeGreaterThan 0
    }

    It 'requires every guard to say why it exists' {
        $matrix = Get-GuardMatrix -Path $script:MatrixPath
        foreach ($guard in $matrix.guards) {
            $guard.why | Should -Not -BeNullOrEmpty -Because "guard '$($guard.id)' must justify itself"
        }
    }

    It 'ships a matrix where hardening changes at least one outcome' {
        $matrix = Get-GuardMatrix -Path $script:MatrixPath
        $diverging = @($matrix.guards | Where-Object { $_.expectDefault -ne $_.expectHardened })
        $diverging.Count | Should -BeGreaterThan 0 -Because 'otherwise the hardened pass proves no remediation boundary'
    }

    It 'ships a matrix where every guard runs as a declared identity' {
        $matrix = Get-GuardMatrix -Path $script:MatrixPath
        $declared = @($matrix.identities.PSObject.Properties.Name)
        $declared.Count | Should -BeGreaterThan 0
        foreach ($guard in $matrix.guards) {
            $guard.identity | Should -BeIn $declared -Because "guard '$($guard.id)' must run as an identity the matrix declares"
        }
    }

    It 'throws on a missing file' {
        { Get-GuardMatrix -Path (Join-Path $PSScriptRoot 'no-such-matrix.json') } |
            Should -Throw -ExpectedMessage '*not found*'
    }

    Context 'refusing an incoherent matrix' {

        BeforeEach {
            $script:TempMatrix = Join-Path ([IO.Path]::GetTempPath()) "guard-matrix-$([guid]::NewGuid()).json"
        }

        AfterEach {
            if (Test-Path -LiteralPath $script:TempMatrix) {
                Remove-Item -LiteralPath $script:TempMatrix -Force
            }
        }

        It 'refuses a matrix with no guards' {
            & $script:WriteMatrix $script:TempMatrix '{ "guards": [] }'
            { Get-GuardMatrix -Path $script:TempMatrix } | Should -Throw -ExpectedMessage '*no guards*'
        }

        It 'refuses a guard missing its expectation' {
            & $script:WriteMatrix $script:TempMatrix @'
{ "guards": [ { "id": "a", "title": "t", "surface": "git", "expectHardened": "Allowed", "severity": "High", "why": "w" } ] }
'@
            { Get-GuardMatrix -Path $script:TempMatrix } | Should -Throw -ExpectedMessage "*missing 'expectDefault'*"
        }

        It 'refuses an expectation that is not a known outcome' {
            & $script:WriteMatrix $script:TempMatrix @'
{ "guards": [ { "id": "a", "title": "t", "surface": "git", "expectDefault": "Probably", "expectHardened": "Allowed", "severity": "High", "why": "w" } ] }
'@
            { Get-GuardMatrix -Path $script:TempMatrix } | Should -Throw -ExpectedMessage '*not a known outcome*'
        }

        It 'refuses a guard that expects Unknown' {
            & $script:WriteMatrix $script:TempMatrix @'
{ "guards": [ { "id": "a", "title": "t", "surface": "git", "expectDefault": "Unknown", "expectHardened": "Allowed", "severity": "High", "why": "w" } ] }
'@
            { Get-GuardMatrix -Path $script:TempMatrix } | Should -Throw -ExpectedMessage "*expects 'Unknown'*"
        }

        It 'refuses duplicate guard ids' {
            & $script:WriteMatrix $script:TempMatrix @'
{ "guards": [
  { "id": "a", "title": "t", "surface": "git", "expectDefault": "Allowed", "expectHardened": "Allowed", "severity": "High", "why": "w" },
  { "id": "a", "title": "t", "surface": "git", "expectDefault": "RefusedByPolicy", "expectHardened": "RefusedByPolicy", "severity": "High", "why": "w" }
] }
'@
            { Get-GuardMatrix -Path $script:TempMatrix } | Should -Throw -ExpectedMessage '*more than once*'
        }

        # The two checks that stop the drill being unfalsifiable.
        It 'refuses a matrix where nothing is expected to hold' {
            & $script:WriteMatrix $script:TempMatrix @'
{ "guards": [ { "id": "a", "title": "t", "surface": "git", "expectDefault": "Allowed", "expectHardened": "Allowed", "severity": "Finding", "why": "w" } ] }
'@
            { Get-GuardMatrix -Path $script:TempMatrix } | Should -Throw -ExpectedMessage '*verifies nothing*'
        }

        It 'refuses a matrix where nothing is expected to give way' {
            & $script:WriteMatrix $script:TempMatrix @'
{ "guards": [ { "id": "a", "title": "t", "surface": "git", "expectDefault": "RefusedByPolicy", "expectHardened": "RefusedByPolicy", "severity": "Critical", "why": "w" } ] }
'@
            { Get-GuardMatrix -Path $script:TempMatrix } |
                Should -Throw -ExpectedMessage '*cannot tell a working policy from a broken connection*'
        }
    }
}

Describe 'Resolve-PushOutcome' {

    It 'reports a clean push as Allowed' {
        (Resolve-PushOutcome -ExitCode 0).Outcome | Should -Be 'Allowed'
    }

    It 'recognises a branch policy refusal' {
        $stderr = '! [remote rejected] main -> main (TF402455: Pushes to this branch are not permitted; you must use a pull request to update this branch.)'
        (Resolve-PushOutcome -ExitCode 1 -Stderr $stderr).Outcome | Should -Be 'RefusedByPolicy'
    }

    It 'recognises a permission refusal as distinct from a policy refusal' {
        $stderr = "TF401027: You need the Git 'ForcePush' permission to perform this action."
        (Resolve-PushOutcome -ExitCode 1 -Stderr $stderr).Outcome | Should -Be 'RefusedByPermission'
    }

    # The whole reason this function exists rather than a boolean.
    It 'does NOT call a failed login a policy refusal' {
        $stderr = 'fatal: Authentication failed for ''https://dev.azure.com/zuqdah-labs/lab/_git/lab'''
        $result = Resolve-PushOutcome -ExitCode 128 -Stderr $stderr
        $result.Outcome | Should -Be 'AuthFailure'
        $result.Outcome | Should -Not -Be 'RefusedByPolicy'
    }

    It 'treats an unauthorised user as an auth failure, not a policy refusal' {
        $stderr = 'TF400813: The user ''abc'' is not authorized to access this resource.'
        (Resolve-PushOutcome -ExitCode 128 -Stderr $stderr).Outcome | Should -Be 'AuthFailure'
    }

    It 'prefers AuthFailure even when the text also mentions permission' {
        # A credential problem often produces both signals. The auth reading is
        # the safe one: it proves nothing, so it cannot become a false pass.
        $stderr = 'fatal: Authentication failed. permission denied'
        (Resolve-PushOutcome -ExitCode 128 -Stderr $stderr).Outcome | Should -Be 'AuthFailure'
    }

    It 'reports an unrecognised failure as Unknown rather than guessing' {
        $result = Resolve-PushOutcome -ExitCode 1 -Stderr 'error: failed to push some refs'
        $result.Outcome | Should -Be 'Unknown'
    }

    It 'never reports Unknown for a successful push' {
        (Resolve-PushOutcome -ExitCode 0 -Stderr 'some noise on stderr').Outcome | Should -Be 'Allowed'
    }
}

Describe 'Resolve-PullRequestOutcome' {

    It 'reports a completed pull request as Allowed' {
        $result = Resolve-PullRequestOutcome -StatusCode 200 -ResultingStatus 'completed'
        $result.Outcome | Should -Be 'Allowed'
    }

    # The asynchronous-completion trap: 200 does not mean merged.
    It 'does NOT treat HTTP 200 as a bypass when the pull request stays active' {
        $result = Resolve-PullRequestOutcome -StatusCode 200 -ResultingStatus 'active'
        $result.Outcome | Should -Be 'RefusedByPolicy'
        $result.Reason | Should -BeLike '*did not happen*'
    }

    It 'recognises an explicit policy error in the body' {
        $result = Resolve-PullRequestOutcome -StatusCode 409 -Body 'TF402484: The pull request cannot be completed because a blocking policy is not met.'
        $result.Outcome | Should -Be 'RefusedByPolicy'
    }

    It 'treats 403 as an auth failure rather than a policy refusal' {
        (Resolve-PullRequestOutcome -StatusCode 403).Outcome | Should -Be 'AuthFailure'
    }

    It 'reports an unclassifiable success as Unknown' {
        (Resolve-PullRequestOutcome -StatusCode 200 -ResultingStatus 'abandoned').Outcome | Should -Be 'Unknown'
    }
}

Describe 'Resolve-ApprovalOutcome' {

    It 'reports Blocked when the deployment did not run and an approval is pending' {
        $result = Resolve-ApprovalOutcome -RunState 'inProgress' -ApprovalPending $true -DeploymentExecuted $false
        $result.Outcome | Should -Be 'Blocked'
    }

    It 'reports Allowed when the deployment ran, whatever the approval says' {
        $result = Resolve-ApprovalOutcome -RunState 'completed' -ApprovalPending $true -DeploymentExecuted $true
        $result.Outcome | Should -Be 'Allowed'
    }

    # A pipeline that fell over on a syntax error also never deployed.
    It 'does NOT report Blocked when nothing was asked for approval' {
        $result = Resolve-ApprovalOutcome -RunState 'completed' -ApprovalPending $false -DeploymentExecuted $false
        $result.Outcome | Should -Be 'Unknown'
        $result.Reason | Should -BeLike '*unrelated reason*'
    }
}

Describe 'Resolve-SecretExposure' {

    It 'reports Masked when the step ran and nothing leaked' {
        $log = "$script:Marker`nvalue is ***`ndone"
        (Resolve-SecretExposure -Log $log -Secret $script:Secret -Marker $script:Marker).Outcome |
            Should -Be 'Masked'
    }

    It 'finds the secret in plain text' {
        $log = "$script:Marker`nvalue is $script:Secret"
        $result = Resolve-SecretExposure -Log $log -Secret $script:Secret -Marker $script:Marker
        $result.Outcome | Should -Be 'Leaked'
        $result.Signal | Should -Be 'plain'
    }

    It 'finds the secret base64-encoded, which masking does not catch' {
        $encoded = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($script:Secret))
        $log = "$script:Marker`nencoded: $encoded"
        $result = Resolve-SecretExposure -Log $log -Secret $script:Secret -Marker $script:Marker
        $result.Outcome | Should -Be 'Leaked'
        $result.Signal | Should -Be 'base64'
    }

    It 'finds the secret reversed' {
        $chars = $script:Secret.ToCharArray()
        [array]::Reverse($chars)
        $log = "$script:Marker`nreversed: $(-join $chars)"
        (Resolve-SecretExposure -Log $log -Secret $script:Secret -Marker $script:Marker).Signal |
            Should -Be 'reversed'
    }

    It 'finds the secret hex-encoded' {
        $hex = -join ([Text.Encoding]::UTF8.GetBytes($script:Secret) | ForEach-Object { $_.ToString('x2') })
        $log = "$script:Marker`nhex: $hex"
        (Resolve-SecretExposure -Log $log -Secret $script:Secret -Marker $script:Marker).Signal |
            Should -Be 'hex'
    }

    It 'finds the secret printed one character at a time' {
        $spaced = ($script:Secret.ToCharArray() -join ' ')
        $log = "$script:Marker`n$spaced"
        $result = Resolve-SecretExposure -Log $log -Secret $script:Secret -Marker $script:Marker
        $result.Outcome | Should -Be 'Leaked'
        $result.Signal | Should -Be 'separated'
    }

    It 'finds the secret printed one character per line' {
        $log = "$script:Marker`n" + ($script:Secret.ToCharArray() -join "`n")
        (Resolve-SecretExposure -Log $log -Secret $script:Secret -Marker $script:Marker).Outcome |
            Should -Be 'Leaked'
    }

    # A clean log from a step that never ran is the false pass this series keeps
    # tripping over. It must not read as evidence of masking.
    It 'reports Unknown when the marker is absent, not Masked' {
        $log = 'some other pipeline output entirely'
        $result = Resolve-SecretExposure -Log $log -Secret $script:Secret -Marker $script:Marker
        $result.Outcome | Should -Be 'Unknown'
        $result.Outcome | Should -Not -Be 'Masked'
    }

    It 'refuses to scan for a secret too short to search for safely' {
        { Resolve-SecretExposure -Log 'x' -Secret 'short' -Marker $script:Marker } |
            Should -Throw -ExpectedMessage '*Refusing to scan*'
    }
}

Describe 'Test-GuardExpectation' {

    BeforeAll {
        $script:Guard = [pscustomobject]@{
            id             = 'push-to-protected-branch'
            title          = 'A direct push to main is refused'
            surface        = 'git'
            expectDefault  = 'RefusedByPolicy'
            expectHardened = 'RefusedByPolicy'
            severity       = 'Critical'
            why            = 'because'
        }
        # The guard whose expectation differs between passes: it is what makes
        # the remediation boundary provable rather than asserted.
        $script:DivergingGuard = [pscustomobject]@{
            id             = 'stale-approval-survives-new-commit'
            title          = 'An approval granted before the code changed still completes the pull request'
            surface        = 'api'
            expectDefault  = 'Allowed'
            expectHardened = 'RefusedByPolicy'
            severity       = 'High'
            why            = 'because'
        }
    }

    It 'passes when the observation matches the expectation' {
        (Test-GuardExpectation -Guard $script:Guard -Pass 'Hardened' -Observed 'RefusedByPolicy').Passed |
            Should -BeTrue
    }

    It 'fails when the control gave way' {
        (Test-GuardExpectation -Guard $script:Guard -Pass 'Hardened' -Observed 'Allowed').Passed |
            Should -BeFalse
    }

    It 'grades the default and hardened passes against different expectations' {
        (Test-GuardExpectation -Guard $script:DivergingGuard -Pass 'Default' -Observed 'Allowed').Passed |
            Should -BeTrue
        (Test-GuardExpectation -Guard $script:DivergingGuard -Pass 'Hardened' -Observed 'Allowed').Passed |
            Should -BeFalse
    }

    It 'fails an Unknown observation even where it would otherwise have matched' {
        $unknowable = [pscustomobject]@{
            id             = 'x'; title = 't'; surface = 'git'
            expectDefault  = 'Allowed'; expectHardened = 'Allowed'
            severity       = 'Finding'; why = 'w'
        }
        $result = Test-GuardExpectation -Guard $unknowable -Pass 'Hardened' -Observed 'Unknown'
        $result.Passed | Should -BeFalse
        $result.Inconclusive | Should -BeTrue
    }
}

Describe 'Get-GuardReport' {

    It 'reports ok when every guard passed' {
        $results = @(
            [pscustomobject]@{ Passed = $true; Inconclusive = $false; Severity = 'Critical' }
            [pscustomobject]@{ Passed = $true; Inconclusive = $false; Severity = 'Finding' }
        )
        $report = Get-GuardReport -Result $results
        $report.Ok | Should -BeTrue
        $report.Findings | Should -Be 1
    }

    It 'is not ok when a guard failed' {
        $results = @([pscustomobject]@{ Passed = $false; Inconclusive = $false; Severity = 'Critical' })
        (Get-GuardReport -Result $results).Ok | Should -BeFalse
    }

    It 'is not ok when a guard was inconclusive' {
        $results = @([pscustomobject]@{ Passed = $false; Inconclusive = $true; Severity = 'Critical' })
        $report = Get-GuardReport -Result $results
        $report.Ok | Should -BeFalse
        $report.Inconclusive | Should -Be 1
    }

    # A drill that graded nothing must not look like a drill that passed.
    It 'is not ok for an empty result set' {
        (Get-GuardReport -Result @()).Ok | Should -BeFalse
    }
}
