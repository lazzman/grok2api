package relational

import (
	"context"
	"time"

	"github.com/chenyme/grok2api/backend/internal/domain/audit"
	"github.com/chenyme/grok2api/backend/internal/repository"
	"gorm.io/gorm"
)

func (r *AccountRepository) accountDegradeHistoryQuery(ctx context.Context, filter repository.AccountListFilter) *gorm.DB {
	input := repository.DegradeSummaryQuery{
		Start: filter.Now.Add(-24 * time.Hour), End: filter.Now,
		SoftTPS: audit.DefaultDegradeSoftTPS, HardTPS: audit.DefaultDegradeHardTPS,
		MinGenerationMS: audit.DefaultDegradeMinGenMS, MinOutputTokens: audit.DefaultDegradeMinOutput,
	}
	if filter.QualityQuery != nil {
		input = *filter.QualityQuery
	}
	return degradeClassifiedQuery(r.db.db.WithContext(ctx), r.db.dialect, input).
		Select("1").Where("a.account_id = provider_accounts.id")
}

func (r *AuditRepository) GetAccountDegradeHistory(ctx context.Context, accountIDs []uint64, input repository.DegradeSummaryQuery) (map[uint64]repository.AccountDegradeHistory, error) {
	result := make(map[uint64]repository.AccountDegradeHistory)
	if len(accountIDs) == 0 {
		return result, nil
	}
	var rows []struct {
		AccountID uint64
		Hits      int64
		Soft      int64
		Hard      int64
		Burst     int64
		Thinking  int64
		LastSeen  degradeTimestamp
	}
	classified := degradeClassifiedQuery(r.db.db.WithContext(ctx), r.db.dialect, input).Where("a.account_id IN ?", accountIDs)
	if err := r.db.db.WithContext(ctx).Table("(?) AS d", classified).Select(`d.account_id, COUNT(*) AS hits,
		SUM(CASE WHEN d.degrade_class = 'soft_tps' THEN 1 ELSE 0 END) AS soft,
		SUM(CASE WHEN d.degrade_class = 'hard_tps' THEN 1 ELSE 0 END) AS hard,
		SUM(CASE WHEN d.degrade_class = 'buffered_burst' THEN 1 ELSE 0 END) AS burst,
		SUM(CASE WHEN d.degrade_class = 'missing_thinking' THEN 1 ELSE 0 END) AS thinking,
		MAX(d.created_at) AS last_seen`).Group("d.account_id").Scan(&rows).Error; err != nil {
		return nil, err
	}
	for _, row := range rows {
		result[row.AccountID] = repository.AccountDegradeHistory{Hits: row.Hits, Soft: row.Soft, Hard: row.Hard, Burst: row.Burst, Thinking: row.Thinking, Last: time.Time(row.LastSeen)}
	}
	return result, nil
}
