package relational

import (
	"context"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/chenyme/grok2api/backend/internal/domain/account"
	egressdomain "github.com/chenyme/grok2api/backend/internal/domain/egress"
	"github.com/chenyme/grok2api/backend/internal/repository"
)

func TestAccountQualityFilter(test *testing.T) {
	ctx := context.Background()
	database, err := OpenSQLite(ctx, filepath.Join(test.TempDir(), "quality-filter.db"))
	if err != nil {
		test.Fatal(err)
	}
	defer database.Close()
	if err := database.InitializeSchema(ctx); err != nil {
		test.Fatal(err)
	}
	now := time.Date(2026, 11, 26, 8, 0, 0, 0, time.UTC)
	future, past := now.Add(time.Hour), now.Add(-time.Hour)
	for _, seed := range []struct {
		name     string
		provider account.Provider
		enabled  bool
		marker   string
		cooldown *time.Time
	}{
		{"clean", account.ProviderBuild, true, "", nil},
		{"network", account.ProviderBuild, true, "upstream status 504", &future},
		{"manual-disabled", account.ProviderBuild, false, "", nil},
		{"legacy-null", account.ProviderBuild, true, "", nil},
		{"cooling", account.ProviderBuild, true, account.LastErrorMissingThinking, &future},
		{"recovered", account.ProviderBuild, true, account.LastErrorMissingThinking, &past},
		{"reenabled", account.ProviderBuild, true, account.LastErrorMissingThinkingDisabled, nil},
		{"history-disabled", account.ProviderBuild, false, account.LastErrorMissingThinking, nil},
		{"quality-disabled", account.ProviderBuild, false, account.LastErrorMissingThinkingDisabled, nil},
		{"console-history", account.ProviderConsole, true, account.LastErrorMissingThinking, nil},
		{"console-disabled", account.ProviderConsole, false, account.LastErrorMissingThinkingDisabled, nil},
		{"web-clean", account.ProviderWeb, true, "", nil},
	} {
		row := accountModel{
			IdentityKey: testIdentityKey(seed.name), Provider: string(seed.provider), Name: seed.name, SourceKey: seed.name,
			Enabled: seed.enabled, AuthStatus: string(account.AuthStatusActive), LastError: seed.marker, CooldownUntil: seed.cooldown,
		}
		if err := database.db.WithContext(ctx).Create(&row).Error; err != nil {
			test.Fatal(err)
		}
		if seed.name == "legacy-null" {
			if err := database.db.WithContext(ctx).Model(&row).Update("last_error", nil).Error; err != nil {
				test.Fatal(err)
			}
		}
	}
	accounts := NewAccountRepository(database)
	for _, scenario := range []struct {
		name     string
		provider string
		quality  string
		status   string
		search   string
		offset   int
		limit    int
		want     []string
	}{
		{name: "不筛选仍返回全部账号", want: []string{"clean", "network", "manual-disabled", "legacy-null", "cooling", "recovered", "reenabled", "history-disabled", "quality-disabled", "console-history", "console-disabled", "web-clean"}},
		{name: "无标记包含空值和其他故障", provider: "grok_build", quality: "none", want: []string{"clean", "network", "manual-disabled", "legacy-null"}},
		{name: "曾降智与标签一致", provider: "grok_build", quality: "history", want: []string{"cooling", "recovered", "reenabled", "history-disabled"}},
		{name: "降智停用不包含人工重新启用账号", provider: "grok_build", quality: "disabled", want: []string{"quality-disabled"}},
		{name: "曾降智与正常状态组合", provider: "grok_build", quality: "history", status: "active", want: []string{"recovered", "reenabled"}},
		{name: "曾降智与冷却状态组合", provider: "grok_build", quality: "history", status: "cooldown", want: []string{"cooling"}},
		{name: "曾降智与手动停用组合", provider: "grok_build", quality: "history", status: "disabled", want: []string{"history-disabled"}},
		{name: "降智停用与正常状态互斥", provider: "grok_build", quality: "disabled", status: "active"},
		{name: "无标记与普通故障冷却组合", provider: "grok_build", quality: "none", status: "cooldown", want: []string{"network"}},
		{name: "搜索与降智筛选组合", provider: "grok_build", quality: "history", search: "reenabled", want: []string{"reenabled"}},
		{name: "搜索不绕过降智筛选", provider: "grok_build", quality: "disabled", search: "reenabled"},
		{name: "筛选后分页且总数不受分页影响", provider: "grok_build", quality: "history", offset: 1, limit: 2, want: []string{"cooling", "recovered", "reenabled", "history-disabled"}},
		{name: "超出末页仍保留正确总数", provider: "grok_build", quality: "disabled", offset: 1, limit: 2, want: []string{"quality-disabled"}},
		{name: "Console曾降智", provider: "grok_console", quality: "history", want: []string{"console-history"}},
		{name: "Console降智停用", provider: "grok_console", quality: "disabled", want: []string{"console-disabled"}},
		{name: "Web无标记", provider: "grok_web", quality: "none", want: []string{"web-clean"}},
		{name: "不指定账号池时跨池筛选", quality: "disabled", want: []string{"quality-disabled", "console-disabled"}},
	} {
		test.Run(scenario.name, func(test *testing.T) {
			limit := scenario.limit
			if limit == 0 {
				limit = 20
			}
			values, total, err := accounts.List(ctx, repository.AccountListQuery{
				Page:   repository.PageQuery{Offset: scenario.offset, Limit: limit, Search: scenario.search, Sort: repository.SortQuery{Field: "name", Direction: repository.SortAscending}},
				Filter: repository.AccountListFilter{Provider: scenario.provider, Quality: scenario.quality, Status: scenario.status, Now: now},
			})
			if err != nil {
				test.Fatal(err)
			}
			if total != int64(len(scenario.want)) {
				test.Fatalf("总数 = %d，期望 %d", total, len(scenario.want))
			}
			want := slices.Clone(scenario.want)
			slices.Sort(want)
			want = want[min(scenario.offset, len(want)):min(scenario.offset+limit, len(want))]
			names := make([]string, 0, len(values))
			for _, value := range values {
				names = append(names, value.Name)
			}
			if !slices.Equal(names, want) {
				test.Fatalf("账号 = %v，期望 %v", names, want)
			}
		})
	}
}

func TestAccountQualityLeaseFilterMatchesMetadataAndRecovery(test *testing.T) {
	ctx := context.Background()
	database, err := OpenSQLite(ctx, filepath.Join(test.TempDir(), "quality-lease-filter.db"))
	if err != nil {
		test.Fatal(err)
	}
	defer database.Close()
	if err := database.InitializeSchema(ctx); err != nil {
		test.Fatal(err)
	}
	nodes := NewEgressRepository(database)
	firstNode, err := nodes.CreateEgressNode(ctx, egressdomain.Node{Name: "隔离出口一", Scope: egressdomain.ScopeBuild, Enabled: true, EncryptedProxyURL: "encrypted"})
	if err != nil {
		test.Fatal(err)
	}
	secondNode, err := nodes.CreateEgressNode(ctx, egressdomain.Node{Name: "隔离出口二", Scope: egressdomain.ScopeBuild, Enabled: true, EncryptedProxyURL: "encrypted"})
	if err != nil {
		test.Fatal(err)
	}
	now := time.Now().UTC()
	until := now.Add(time.Hour)
	ids := map[string]uint64{}
	for _, name := range []string{"active", "expired", "boundary", "rebound", "disabled", "reauth", "history", "both"} {
		row := accountModel{IdentityKey: testIdentityKey(name), Name: name, SourceKey: name, Provider: "grok_build", Enabled: name != "disabled", AuthStatus: "active"}
		if name == "reauth" {
			row.AuthStatus = "reauthRequired"
		}
		if name == "rebound" {
			row.EgressNodeID = &secondNode.ID
		}
		if name == "history" || name == "both" {
			row.LastError = account.LastErrorMissingThinking
		}
		if err := database.db.Create(&row).Error; err != nil {
			test.Fatal(err)
		}
		ids[name] = row.ID
		if name == "history" {
			continue
		}
		deadline := until
		if name == "expired" {
			deadline = now.Add(-time.Second)
		}
		if name == "boundary" {
			deadline = now
		}
		if err := database.db.Create(&accountEgressLeaseBlockModel{AccountID: row.ID, NodeID: firstNode.ID, Reason: "soft_tps", Version: "quality-test-version", CooldownUntil: deadline, UpdatedAt: now}).Error; err != nil {
			test.Fatal(err)
		}
	}
	longer := until.Add(time.Hour)
	if err := database.db.Create(&accountEgressLeaseBlockModel{AccountID: ids["active"], NodeID: secondNode.ID, Reason: "hard_tps", Version: "quality-second-version", CooldownUntil: longer, UpdatedAt: now}).Error; err != nil {
		test.Fatal(err)
	}
	accounts := NewAccountRepository(database)
	for _, scenario := range []struct {
		quality string
		status  string
		want    []string
	}{
		{"quarantined", "", []string{"active", "both"}},
		{"marked", "", []string{"active", "both", "history"}},
		{"none", "", []string{"boundary", "disabled", "expired", "reauth", "rebound"}},
		{"history", "", []string{"both", "history"}},
		{"quarantined", "active", nil},
		{"quarantined", "disabled", nil},
		{"disabled", "", nil},
		{"quarantined", "cooldown", []string{"active", "both"}},
	} {
		test.Run(scenario.quality+"/"+scenario.status, func(test *testing.T) {
			values, total, err := accounts.List(ctx, repository.AccountListQuery{
				Page:   repository.PageQuery{Limit: 20, Sort: repository.SortQuery{Field: "name", Direction: repository.SortAscending}},
				Filter: repository.AccountListFilter{Quality: scenario.quality, Status: scenario.status, Now: now},
			})
			if err != nil {
				test.Fatal(err)
			}
			var names []string
			for _, value := range values {
				names = append(names, value.Name)
			}
			if !slices.Equal(names, scenario.want) || total != int64(len(scenario.want)) {
				test.Fatalf("筛选结果 = %v，总数 = %d，期望 %v", names, total, scenario.want)
			}
		})
	}
	blocks, err := accounts.GetActiveEgressLeaseBlocks(ctx, []uint64{ids["active"], ids["expired"], ids["boundary"], ids["rebound"], ids["disabled"], ids["reauth"], ids["history"]}, now)
	if err != nil || len(blocks) != 1 || !blocks[ids["active"]].CooldownUntil.Equal(longer) || blocks[ids["active"]].Reason != "hard_tps" {
		test.Fatalf("仅加载指定账号的有效隔离，选取最晚截止时间：%#v，%v", blocks, err)
	}
	summary, err := accounts.Summarize(ctx, now)
	if err != nil || len(summary) != 1 || summary[0].Cooldown != 2 || summary[0].Available != 4 {
		test.Fatalf("隔离账号不应计入可用：%#v，%v", summary, err)
	}
	blocks, err = accounts.GetActiveEgressLeaseBlocks(ctx, []uint64{ids["active"]}, longer)
	if err != nil || len(blocks) != 0 {
		test.Fatalf("到期后隔离应消失：%#v，%v", blocks, err)
	}
	if err := database.db.Model(&egressNodeModel{}).Where("id IN ?", []uint64{firstNode.ID, secondNode.ID}).Update("enabled", false).Error; err != nil {
		test.Fatal(err)
	}
	blocks, err = accounts.GetActiveEgressLeaseBlocks(ctx, []uint64{ids["active"], ids["both"]}, now)
	if err != nil || len(blocks) != 0 {
		test.Fatalf("出口已停用，不展示残留隔离：%#v，%v", blocks, err)
	}
}
