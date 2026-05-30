const User = require('../models/User');

const INSUFFICIENT_CREDITS_CODE = 'INSUFFICIENT_CREDITS';

function isCreditsExempt(user) {
  return user && user.role === 'admin';
}

async function getUserCredits(userId) {
  const user = await User.findById(userId).select('credits role');
  if (!user) return null;
  return user;
}

async function ensureCredits(userId, amount = 1) {
  const user = await getUserCredits(userId);
  if (!user) {
    const err = new Error('User not found');
    err.statusCode = 404;
    throw err;
  }
  if (isCreditsExempt(user)) {
    return { user, remaining: Infinity };
  }
  if ((user.credits || 0) < amount) {
    const err = new Error('Credits exhausted. Contact admin to add more credits.');
    err.statusCode = 402;
    err.code = INSUFFICIENT_CREDITS_CODE;
    throw err;
  }
  return { user, remaining: user.credits };
}

async function deductCredits(userId, amount = 1) {
  const user = await getUserCredits(userId);
  if (!user) {
    const err = new Error('User not found');
    err.statusCode = 404;
    throw err;
  }
  if (isCreditsExempt(user)) {
    return { remaining: user.credits || 0, deducted: 0 };
  }

  const updated = await User.findOneAndUpdate(
    { _id: userId, credits: { $gte: amount } },
    { $inc: { credits: -amount } },
    { new: true }
  ).select('credits role');

  if (!updated) {
    const err = new Error('Credits exhausted. Contact admin to add more credits.');
    err.statusCode = 402;
    err.code = INSUFFICIENT_CREDITS_CODE;
    throw err;
  }

  return { remaining: updated.credits, deducted: amount };
}

async function consumeCredits(userId, amount = 1) {
  return deductCredits(userId, amount);
}

function sendCreditsError(res, error) {
  return res.status(error.statusCode || 402).json({
    success: false,
    code: error.code || INSUFFICIENT_CREDITS_CODE,
    message: error.message || 'Credits exhausted. Contact admin to add more credits.',
  });
}

module.exports = {
  INSUFFICIENT_CREDITS_CODE,
  isCreditsExempt,
  ensureCredits,
  deductCredits,
  consumeCredits,
  sendCreditsError,
};
