@{
    Severity     = @('Error', 'Warning')
    ExcludeRules = @(
        # Console progress for analysts / EDR session transcripts is intentional.
        'PSAvoidUsingWriteHost',
        # Collector functions share a uniform (Context) signature; not every collector reads it.
        'PSReviewUnusedParameter',
        # Names like Get-IRServices / Get-IRProcesses describe collections on purpose.
        'PSUseSingularNouns',
        # Internal helpers named New-*/Set-* do not change system state.
        'PSUseShouldProcessForStateChangingFunctions',
        # Collectors deliberately swallow per-item failures (one bad item must not abort collection).
        'PSAvoidUsingEmptyCatchBlock'
    )
}
