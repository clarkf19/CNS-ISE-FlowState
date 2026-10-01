"""A simple in-memory banking service: the application the gateway protects."""

from __future__ import annotations

import itertools
import threading
from dataclasses import dataclass
from typing import Any, Callable

DEFAULT_ACCOUNTS = {"alice": 5_000, "bob": 1_000, "carol": 0, "root": 0}
MAX_AMOUNT = 10**12


class ServiceError(Exception):
    pass


@dataclass
class Account:
    balance: int
    frozen: bool = False


class TransactionService:
    def __init__(self, accounts: dict[str, int] | None = None) -> None:
        source = DEFAULT_ACCOUNTS if accounts is None else accounts
        self.accounts = {name: Account(bal) for name, bal in source.items()}
        self.ledger: list[dict[str, Any]] = []
        self._tx_ids = itertools.count(1)
        self._lock = threading.Lock()
        self._ops: dict[str, Callable[[str, dict], dict]] = {
            "balance": self._balance,
            "transfer": self._transfer,
            "list_accounts": self._list_accounts,
            "freeze_account": self._freeze_account,
            "create_account": self._create_account,
        }

    def operations(self) -> list[str]:
        return sorted(self._ops)

    def execute(self, client_id: str, operation: str, params: dict) -> dict:
        handler = self._ops.get(operation)
        if handler is None:
            raise ServiceError(f"unknown operation {operation!r}")
        with self._lock:
            return handler(client_id, params)

    def _account(self, name: Any) -> Account:
        if not isinstance(name, str) or name not in self.accounts:
            raise ServiceError(f"no such account {name!r}")
        return self.accounts[name]

    @staticmethod
    def _amount(value: Any) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or not 0 < value <= MAX_AMOUNT:
            raise ServiceError("amount must be a positive integer")
        return value

    def _balance(self, client_id: str, params: dict) -> dict:
        return {"account": client_id, "balance": self._account(client_id).balance}

    def _transfer(self, client_id: str, params: dict) -> dict:
        amount = self._amount(params.get("amount"))
        to = params.get("to")
        src, dst = self._account(client_id), self._account(to)
        if to == client_id:
            raise ServiceError("cannot transfer to the same account")
        if src.frozen or dst.frozen:
            raise ServiceError("account is frozen")
        if src.balance < amount:
            raise ServiceError("insufficient funds")
        src.balance -= amount
        dst.balance += amount
        tx = {"tx_id": next(self._tx_ids), "from": client_id, "to": to, "amount": amount}
        self.ledger.append(tx)
        return {**tx, "balance": src.balance}

    def _list_accounts(self, client_id: str, params: dict) -> dict:
        return {
            "accounts": [
                {"account": name, "balance": a.balance, "frozen": a.frozen}
                for name, a in sorted(self.accounts.items())
            ]
        }

    def _freeze_account(self, client_id: str, params: dict) -> dict:
        account = self._account(params.get("account"))
        account.frozen = bool(params.get("frozen", True))
        return {"account": params["account"], "frozen": account.frozen}

    def _create_account(self, client_id: str, params: dict) -> dict:
        name = params.get("account")
        if not isinstance(name, str) or not name or name in self.accounts:
            raise ServiceError("account name missing or already exists")
        initial = params.get("initial", 0)
        if initial != 0:
            initial = self._amount(initial)
        self.accounts[name] = Account(initial)
        return {"account": name, "balance": initial}
