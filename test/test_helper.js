const _sodium = require('./sodium-chloride')(require('sodium-native'))

module.exports = class SodiumHelper {
    static async init() {
        if (_sodium.ready != null) {
            await _sodium.ready; 
        }
        return _sodium;
    }
};
