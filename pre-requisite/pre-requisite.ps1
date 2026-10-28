# Define emergency access account Object IDs
$breakGlassObjectIds = @(
    '755e716a-2527-4710-9cf8-2af04120b100', # Object ID for Emergency Break-Glass 1
    '6be4e3ed-4a20-4988-a625-5e089f9e2450'  # Object ID for Emergency Break-Glass 2
)

# Verify at least two verified emergency account IDs are declared before continuing
if ($breakGlassObjectIds.Count -lt 2 -or $breakGlassObjectIds -match '^<') {
    throw 'Provide at least two verified emergency access object identifiers.'
}