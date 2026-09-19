package fs

import (
	"path/filepath"
	"testing"
)

// workspaceRoot returns a temporary directory with every symlink resolved.
//
// Git reports the resolved top level, so on a host whose temporary directory
// sits behind a symlink (macOS /var) an unresolved root looks like a foreign
// repository boundary and the inventory fails closed. Resolving first keeps
// these tests measuring the workspace rule instead of the host's layout.
func workspaceRoot(t *testing.T) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve temporary root: %v", err)
	}
	return resolved
}

func managedSet(report *SafeInventory) map[string]bool {
	managed := map[string]bool{}
	for _, path := range report.ManagedCandidates {
		managed[path] = true
	}
	return managed
}

// TestSafeInventoryWorkspaceUsesNestedGitAuthority pins the workspace rule: a
// root that is not a repository still honours each nested repository's tracked,
// untracked, and ignored authority, and paths outside every repository stay on
// the traversal route.
func TestSafeInventoryWorkspaceUsesNestedGitAuthority(t *testing.T) {
	root := workspaceRoot(t)

	gitCommand(t, root, "init", "-q", "repoA")
	mustWrite(t, root, "repoA/.gitignore", "ignored.private\nbundle/\n")
	mustWrite(t, root, "repoA/tracked.go", "package source\n")
	mustWrite(t, root, "repoA/ignored.private", "must never be inventoried\n")
	mustWrite(t, root, "repoA/bundle/pack.js", "generated bundle\n")
	gitCommand(t, root+"/repoA", "add", ".gitignore", "tracked.go")
	mustWrite(t, root, "repoA/added.go", "package source\n")

	gitCommand(t, root, "init", "-q", "repoB")
	mustWrite(t, root, "repoB/.gitignore", "cache.private\n")
	mustWrite(t, root, "repoB/tracked.py", "print('tracked')\n")
	mustWrite(t, root, "repoB/cache.private", "cache payload\n")
	gitCommand(t, root+"/repoB", "add", ".gitignore", "tracked.py")

	mustWrite(t, root, "loose.txt", "outside every repository\n")

	report, err := BuildSafeInventory(root, WalkOptions{})
	if err != nil {
		t.Fatal(err)
	}
	managed := managedSet(report)

	for _, path := range []string{
		"loose.txt",
		"repoA/.gitignore", "repoA/tracked.go", "repoA/added.go",
		"repoB/.gitignore", "repoB/tracked.py",
	} {
		if !managed[path] {
			t.Fatalf("expected managed path %s: %#v", path, report.ManagedCandidates)
		}
	}
	for _, path := range []string{
		"repoA/ignored.private", "repoA/bundle/pack.js", "repoB/cache.private",
	} {
		if managed[path] {
			t.Fatalf("nested Git-ignored path became managed: %s", path)
		}
		if category := exclusionCategory(report, path); category != SafetyIgnored {
			t.Fatalf("nested ignored path %s must be excluded as %s, got %q", path, SafetyIgnored, category)
		}
	}
	if report.Summary.GitRepository {
		t.Fatalf("a workspace root is not itself a repository: %#v", report.Summary)
	}
	if report.Summary.GitTracked != 4 || report.Summary.Ignored != 3 {
		t.Fatalf("nested Git authority facts are missing: %#v", report.Summary)
	}
	if report.Summary.NonignoredUntracked != 2 {
		t.Fatalf("loose and nested untracked paths must stay eligible: %#v", report.Summary)
	}
}

// TestSafeInventoryWorkspaceRolesMatchARepositoryRoot pins the equivalence the
// workspace rule exists for: the same layout at a repository root and inside a
// nested repository must produce the same roles and exclusion categories.
func TestSafeInventoryWorkspaceRolesMatchARepositoryRoot(t *testing.T) {
	root := workspaceRoot(t)
	repository := filepath.Join(root, "service")
	gitCommand(t, root, "init", "-q", "service")
	mustWrite(t, root, "service/.gitignore", "secret.private\nout/\n")
	mustWrite(t, root, "service/main.go", "package main\n")
	mustWrite(t, root, "service/secret.private", "hidden\n")
	mustWrite(t, root, "service/out/app.bin", "artifact\n")
	gitCommand(t, repository, "add", ".gitignore", "main.go")

	atRoot, err := BuildSafeInventory(repository, WalkOptions{})
	if err != nil {
		t.Fatal(err)
	}
	inWorkspace, err := BuildSafeInventory(root, WalkOptions{})
	if err != nil {
		t.Fatal(err)
	}

	rootManaged := managedSet(atRoot)
	workspaceManaged := managedSet(inWorkspace)
	if len(rootManaged) != len(workspaceManaged) {
		t.Fatalf("managed sets differ in size: %#v vs %#v", rootManaged, workspaceManaged)
	}
	for path := range rootManaged {
		if !workspaceManaged["service/"+path] {
			t.Fatalf("repository-root path %s has no workspace twin: %#v", path, workspaceManaged)
		}
	}
	for _, path := range []string{"secret.private", "out/app.bin"} {
		if atRoot.Summary.Ignored == 0 {
			t.Fatalf("repository root must see its ignored paths: %#v", atRoot.Summary)
		}
		if category := exclusionCategory(inWorkspace, "service/"+path); category != exclusionCategory(atRoot, path) {
			t.Fatalf("workspace exclusion for %s is %q, repository root says %q",
				path, category, exclusionCategory(atRoot, path))
		}
	}
	if atRoot.Summary.NonignoredUntracked != inWorkspace.Summary.NonignoredUntracked ||
		atRoot.Summary.GitTracked != inWorkspace.Summary.GitTracked {
		t.Fatalf("workspace facts diverge from the repository root: %#v vs %#v", atRoot.Summary, inWorkspace.Summary)
	}
}

// TestSafeInventoryWithoutNestedRepositoryKeepsTraversal guards the zero-cost
// path: an ordinary non-Git directory must still be inventoried by traversal,
// with no Git question asked.
func TestSafeInventoryWithoutNestedRepositoryKeepsTraversal(t *testing.T) {
	root := workspaceRoot(t)
	mustWrite(t, root, "docs/readme.md", "notes\n")
	mustWrite(t, root, "data/facts.json", "{}\n")

	report, err := BuildSafeInventory(root, WalkOptions{})
	if err != nil {
		t.Fatal(err)
	}
	managed := managedSet(report)
	if !managed["docs/readme.md"] || !managed["data/facts.json"] {
		t.Fatalf("plain traversal paths must stay managed: %#v", report.ManagedCandidates)
	}
	if report.Summary.GitRepository || report.Summary.GitTracked != 0 || report.Summary.Ignored != 0 {
		t.Fatalf("a plain directory must not claim Git authority: %#v", report.Summary)
	}
}

// TestSafeInventoryWorkspaceRefusesUnverifiableBoundary keeps the fail-closed
// rule: a .git entry that Git does not confirm as a repository boundary must
// not silently degrade to traversal, because ignored content would return to
// the inventory.
func TestSafeInventoryWorkspaceRefusesUnverifiableBoundary(t *testing.T) {
	root := workspaceRoot(t)
	mustWrite(t, root, "service/.git", "gitdir: ../../elsewhere\n")
	mustWrite(t, root, "service/main.go", "package main\n")

	if _, err := BuildSafeInventory(root, WalkOptions{}); err == nil {
		t.Fatal("an unverifiable nested .git boundary must fail closed")
	}
}
