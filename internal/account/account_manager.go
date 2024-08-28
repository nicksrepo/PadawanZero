package account

import (
	"errors"
	"fmt"
	"sync"

	"github.com/kr/pretty"
	"github.com/nicksrepo/padawanzero/internal/state"

	"gonum.org/v1/gonum/mat"
)

type Account struct {
	Address string
	Balance float64
}

// AccountManager manages all accounts in the system
type AccountManager struct {
	accounts map[string]*Account
	indexer  map[int]string
	mutex    sync.RWMutex
	state    *state.Matrix
}

// NewAccountManager creates a new AccountManager
func NewAccountManager() *AccountManager {
	return &AccountManager{
		accounts: make(map[string]*Account),
		state:    &state.Matrix{Data: mat.NewDense(1, 1, []float64{0.0})},
	}
}

func (am *AccountManager) CreateAccount(address string, initialBalance float64) error {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	if _, exists := am.accounts[address]; exists {
		return errors.New("account already exists")
	}

	account := &Account{
		Address: address,
		Balance: initialBalance,
	}

	am.accounts[address] = account

	// Update the state matrix
	rows, _ := am.state.Data.Dims()
	newData := make([]float64, rows+1)
	copy(newData, am.state.Data.RawMatrix().Data)
	newData[rows] = initialBalance
	am.state.Data = mat.NewDense(rows+1, 1, newData)

	return nil
}

func (am *AccountManager) GetBalance(address string) (float64, error) {
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	account, exists := am.accounts[address]
	if !exists {
		return 0, errors.New("account not found")
	}

	return account.Balance, nil
}

func (am *AccountManager) Transfer(from, to string, amount float64) error {
	am.mutex.Lock()
	defer am.mutex.Unlock()

	fromAccount, exists := am.accounts[from]
	if !exists {
		return errors.New("sender account not found")
	}

	toAccount, exists := am.accounts[to]
	if !exists {
		return errors.New("recipient account not found")
	}

	if fromAccount.Balance < amount {
		return errors.New("insufficient funds")
	}

	fromAccount.Balance -= amount
	toAccount.Balance += amount

	// Update the state matrix
	fromIndex := am.getAccountIndex(from)
	toIndex := am.getAccountIndex(to)

	if fromIndex != -1 {
		am.state.Data.Set(fromIndex, 0, fromAccount.Balance)
	}
	if toIndex != -1 {
		am.state.Data.Set(toIndex, 0, toAccount.Balance)
	}

	return nil
}

func (am *AccountManager) getAccountIndex(address string) int {
	i := 0
	for addr := range am.accounts {
		if addr == address {
			return i
		}
		i++
	}
	return -1
}

func (am *AccountManager) PrintAccounts() {
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	fmt.Println("Accounts:")
	for address, account := range am.accounts {
		pretty.Logln("%s: %.2f\n", address, account.Balance)
	}
}

func (am *AccountManager) GetState() *state.Matrix {
	am.mutex.RLock()
	defer am.mutex.RUnlock()

	rows, cols := am.state.Data.Dims()
	return &state.Matrix{
		Data: mat.NewDense(rows, cols, am.state.Data.RawMatrix().Data),
	}
}
