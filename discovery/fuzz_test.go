package discovery

import "testing"

func FuzzParseLegacyPeers(f *testing.F) {
	f.Add("a=1.2.3.4:1")
	f.Add("b")
	f.Add("")
	f.Fuzz(func(t *testing.T, entry string) {
		peers := ParseLegacyPeers([]string{entry})
		for _, p := range peers {
			if p.ID == "" && p.Address == "" {
				t.Fatalf("empty peer from %q", entry)
			}
		}
	})
}

func FuzzPodSANs(f *testing.F) {
	f.Add("sts-0", "sts", "h", "n", "cluster.local")
	f.Fuzz(func(t *testing.T, host, sts, headless, namespace, domain string) {
		cfg := &Config{StatefulSetName: sts, HeadlessService: headless, Namespace: namespace, ClusterDomain: domain}
		dns, ips := PodSANs(cfg, host)
		seen := map[string]bool{}
		for _, name := range dns {
			if seen[name] {
				t.Fatalf("duplicate SAN %q", name)
			}
			seen[name] = true
		}
		if len(ips) != 1 {
			t.Fatalf("ips = %v", ips)
		}
	})
}
