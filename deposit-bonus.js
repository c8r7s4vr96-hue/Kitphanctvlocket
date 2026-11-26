'use strict';

const DEPOSIT_BONUS_TIERS = [
  { minVnd: 1000000, bonusPercent: 35 },
  { minVnd: 500000, bonusPercent: 20 },
  { minVnd: 200000, bonusPercent: 5 },
  { minVnd: 50000, bonusPercent: 0 },
];

function calculateDepositBonus(amountVnd) {
  const amount = Math.round(Number(amountVnd) || 0);
  if (!Number.isSafeInteger(amount) || amount <= 0) {
    return { amount: 0, bonusPercent: 0, bonusVnd: 0, creditedAmount: 0 };
  }
  const tier = DEPOSIT_BONUS_TIERS.find((t) => amount >= t.minVnd);
  const bonusPercent = tier ? tier.bonusPercent : 0;
  const bonusVnd = Math.round((amount * bonusPercent) / 100);
  return {
    amount,
    bonusPercent,
    bonusVnd,
    creditedAmount: amount + bonusVnd,
  };
}

module.exports = { DEPOSIT_BONUS_TIERS, calculateDepositBonus };
