package relational

import (
	"context"
	"time"

	"github.com/chenyme/grok2api/backend/internal/domain/account"
)

const accountQualityLeaseEligibilityPredicate = `provider_accounts.provider = 'grok_build'
 AND provider_accounts.enabled = TRUE AND provider_accounts.auth_status = 'active'
 AND (provider_accounts.egress_node_id IS NULL OR provider_accounts.egress_node_id = quality_lease.node_id)
 AND quality_node.enabled = TRUE AND quality_node.scope = 'grok_build'`

const accountQualityLeasePredicatePrefix = `(EXISTS (SELECT 1 FROM account_egress_lease_blocks quality_lease
 JOIN egress_nodes quality_node ON quality_node.id = quality_lease.node_id
 WHERE quality_lease.account_id = provider_accounts.id AND ` + accountQualityLeaseEligibilityPredicate + `
 AND quality_lease.cooldown_until > `

const accountActiveQualityLeasePredicate = accountQualityLeasePredicatePrefix + `?))`
const accountCurrentQualityLeasePredicate = accountQualityLeasePredicatePrefix + `CURRENT_TIMESTAMP))`

func (r *AccountRepository) GetActiveEgressLeaseBlocks(ctx context.Context, accountIDs []uint64, now time.Time) (map[uint64]account.EgressLeaseBlock, error) {
	result := make(map[uint64]account.EgressLeaseBlock)
	if len(accountIDs) == 0 {
		return result, nil
	}
	var rows []accountEgressLeaseBlockModel
	if err := r.db.db.WithContext(ctx).Model(&accountModel{}).
		Select("quality_lease.*").
		Joins("JOIN account_egress_lease_blocks quality_lease ON quality_lease.account_id = provider_accounts.id").
		Joins("JOIN egress_nodes quality_node ON quality_node.id = quality_lease.node_id").
		Where("provider_accounts.id IN ?", accountIDs).
		Where(accountQualityLeaseEligibilityPredicate).
		Where("quality_lease.cooldown_until > ?", now.UTC()).
		Order("quality_lease.cooldown_until DESC, quality_lease.node_id ASC").
		Scan(&rows).Error; err != nil {
		return nil, err
	}
	for _, row := range rows {
		if _, exists := result[row.AccountID]; !exists {
			result[row.AccountID] = egressLeaseBlockFromModel(row)
		}
	}
	return result, nil
}
