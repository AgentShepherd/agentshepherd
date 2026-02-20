package sandbox

// testRule implements SecurityRule for unit tests.
type testRule struct {
	name       string
	enabled    *bool
	paths      []string
	except     []string
	operations []string
	hosts      []string
}

func (r *testRule) IsEnabled() bool {
	if r.enabled == nil {
		return true
	}
	return *r.enabled
}
func (r *testRule) GetName() string          { return r.name }
func (r *testRule) GetBlockPaths() []string  { return r.paths }
func (r *testRule) GetBlockExcept() []string { return r.except }
func (r *testRule) GetActions() []string     { return r.operations }
func (r *testRule) GetBlockHosts() []string  { return r.hosts }
