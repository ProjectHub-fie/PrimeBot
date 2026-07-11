function getBetaFeatureCandidates(commandName, subcommandName, subcommandGroup) {
  const candidates = [];
  if (commandName) candidates.push(commandName);
  if (subcommandGroup) candidates.push(subcommandGroup);
  if (subcommandName) candidates.push(subcommandName);
  if (commandName && subcommandName) candidates.push(`${commandName}:${subcommandName}`);
  if (commandName && subcommandGroup) candidates.push(`${commandName}:${subcommandGroup}`);
  if (commandName && subcommandGroup && subcommandName) {
    candidates.push(`${commandName}:${subcommandGroup}:${subcommandName}`);
  }
  return [...new Set(candidates.filter(Boolean))];
}

function isBetaFeature(commandName, subcommandName, subcommandGroup, betaFeatures = null) {
  const featureList = Array.isArray(betaFeatures) ? betaFeatures : require('../config').betaFeatures;
  const candidates = getBetaFeatureCandidates(commandName, subcommandName, subcommandGroup);
  return candidates.some(candidate => Array.isArray(featureList) && featureList.includes(candidate));
}

module.exports = {
  getBetaFeatureCandidates,
  isBetaFeature,
};
