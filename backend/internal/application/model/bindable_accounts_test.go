package model

import (
	"context"
	"fmt"
	"testing"

	"github.com/chenyme/grok2api/backend/internal/domain/account"
	"github.com/chenyme/grok2api/backend/internal/repository"
)

type bindableAccountListRepository struct {
	repository.AccountRepository
	total   int
	offsets []int
}

func (r *bindableAccountListRepository) List(_ context.Context, query repository.AccountListQuery) ([]account.Credential, int64, error) {
	r.offsets = append(r.offsets, query.Page.Offset)
	start := query.Page.Offset
	if start > r.total {
		start = r.total
	}
	end := start + query.Page.Limit
	if end > r.total {
		end = r.total
	}
	values := make([]account.Credential, 0, end-start)
	for index := start; index < end; index++ {
		values = append(values, account.Credential{ID: uint64(index + 1), Name: fmt.Sprintf("account-%d", index+1)})
	}
	return values, int64(r.total), nil
}

func TestListBindableAccountsReturnsAllAccountsAcrossPages(t *testing.T) {
	const accountCount = repository.MaxPageSize*2 + 501
	accountRepository := &bindableAccountListRepository{total: accountCount}
	service := &Service{accounts: accountRepository}

	values, err := service.ListBindableAccounts(context.Background(), account.ProviderBuild)
	if err != nil {
		t.Fatalf("ListBindableAccounts() error = %v", err)
	}
	if len(values) != accountCount {
		t.Fatalf("ListBindableAccounts() returned %d accounts, want %d", len(values), accountCount)
	}
	if got := values[len(values)-1].ID; got != accountCount {
		t.Fatalf("last account ID = %d, want %d", got, accountCount)
	}
	wantOffsets := []int{0, repository.MaxPageSize, repository.MaxPageSize * 2}
	if len(accountRepository.offsets) != len(wantOffsets) {
		t.Fatalf("list offsets = %v, want %v", accountRepository.offsets, wantOffsets)
	}
	for index, want := range wantOffsets {
		if accountRepository.offsets[index] != want {
			t.Fatalf("list offset %d = %d, want %d", index, accountRepository.offsets[index], want)
		}
	}
}
