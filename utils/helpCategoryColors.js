function getHelpCategoryColor(category, config = require('../config')) {
    const colors = config?.colors || {};

    switch (category) {
        case 'general':
            return colors.primary || '#5865F2';
        case 'leveling':
            return colors.success || '#57F287';
        case 'games':
            return colors.warning || '#FEE75C';
        case 'moderation':
            return colors.secondary || colors.primary || '#5865F2';
        case 'community':
            return colors.success || '#57F287';
        case 'admin':
            return colors.error || '#ED4245';
        default:
            return colors.primary || '#5865F2';
    }
}

module.exports = {
    getHelpCategoryColor,
};
