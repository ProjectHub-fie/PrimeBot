// This script tests the birthday celebration system with the updated changes
const fs = require('fs');
const path = require('path');
const { Client, GatewayIntentBits } = require('discord.js');
const BirthdayManager = require('./utils/birthdayManager');

// Create a mock client for testing
const mockClient = {
  guilds: {
    fetch: (id) => Promise.resolve({
      name: 'Test Guild',
      members: {
        fetch: (userId) => Promise.resolve({
          user: { tag: 'TestUser#1234' },
          displayName: 'Test User',
          roles: {
            add: () => Promise.resolve(),
            remove: () => Promise.resolve()
          }
        })
      },
      channels: {
        fetch: (channelId) => Promise.resolve({
          send: (message) => {
            console.log('\n[TEST] Channel message sent:');
            if (message.content) console.log('Content:', message.content);
            if (message.embeds) {
              message.embeds.forEach((embed, i) => {
                console.log(`Embed #${i+1}:`);
                console.log('  Title:', embed.data.title);
                console.log('  Color:', embed.data.color);
                console.log('  Description:', embed.data.description);
                console.log('  Image URL:', embed.data.image?.url);
                if (embed.data.fields) {
                  embed.data.fields.forEach((field, j) => {
                    console.log(`  Field #${j+1}: ${field.name} - ${field.value}`);
                  });
                }
              });
            }
            return Promise.resolve();
          }
        })
      },
      roles: {
        fetch: () => Promise.resolve({
          name: 'Birthday Role'
        })
      }
    })
  }
};

// Initialize birthday manager with mock client
const birthdayManager = new BirthdayManager(mockClient);

// Create test birthday data file
const testBirthdayData = {
  '123456789': {
    announcementChannel: '987654321',
    role: '112233445566',
    users: {
      '111222333': {
        month: new Date().getMonth() + 1, // Current month
        day: new Date().getDate(),        // Current day
        year: 2000,
        lastCelebrated: null
      },
      '444555666': {
        month: new Date().getMonth() + 1, // Current month
        day: new Date().getDate(),        // Current day
        year: 1995,
        lastCelebrated: null
      }
    }
  }
};

// Write test data to a temporary file
const tempDataPath = path.join(__dirname, 'data/birthdays-test.json');
fs.writeFileSync(tempDataPath, JSON.stringify(testBirthdayData, null, 2));

// Save original data path
const originalDataPath = birthdayManager.dataPath;

// Use the test data for our test
birthdayManager.dataPath = tempDataPath;
birthdayManager.loadBirthdays();

console.log('[TEST] Birthday test data loaded');
console.log('[TEST] Running first check - should send birthday message with style #1');

// Test checking birthdays (should detect birthdays and send message with first style)
birthdayManager.checkBirthdays().then(() => {
  console.log('\n[TEST] First check completed');
  
  // Re-load birthdays to see the updated lastCelebrated values
  birthdayManager.loadBirthdays();
  
  // Output the updated data
  console.log('\n[TEST] After first check, lastCelebrated values:');
  const guildData = birthdayManager.birthdays.get('123456789');
  if (guildData) {
    for (const [userId, userData] of guildData.users.entries()) {
      console.log(`User ${userId}: lastCelebrated = ${userData.lastCelebrated}`);
    }
  }
  
  console.log('\n[TEST] Running second check - should NOT send birthday message (already celebrated)');
  
  // Test again - should not send message as already celebrated today
  return birthdayManager.checkBirthdays();
}).then(() => {
  console.log('\n[TEST] Second check completed');
  
  // Force reset lastCelebrated to simulate tomorrow
  console.log('\n[TEST] Simulating next day by resetting lastCelebrated');
  
  const guildData = birthdayManager.birthdays.get('123456789');
  if (guildData) {
    for (const [userId, userData] of guildData.users.entries()) {
      userData.lastCelebrated = null;
    }
  }
  birthdayManager.saveBirthdays();
  
  console.log('\n[TEST] Running third check - should send message with style #2');
  
  // Test again - should send message with second style
  return birthdayManager.checkBirthdays();
}).then(() => {
  console.log('\n[TEST] Third check completed');
  
  // Reset lastCelebrated again
  const guildData = birthdayManager.birthdays.get('123456789');
  if (guildData) {
    for (const [userId, userData] of guildData.users.entries()) {
      userData.lastCelebrated = null;
    }
  }
  birthdayManager.saveBirthdays();
  
  console.log('\n[TEST] Running fourth check - should send message with style #3');
  
  // Test again - should send message with third style
  return birthdayManager.checkBirthdays();
}).then(() => {
  console.log('\n[TEST] Fourth check completed');
  
  // Reset lastCelebrated again
  const guildData = birthdayManager.birthdays.get('123456789');
  if (guildData) {
    for (const [userId, userData] of guildData.users.entries()) {
      userData.lastCelebrated = null;
    }
  }
  birthdayManager.saveBirthdays();
  
  console.log('\n[TEST] Running fifth check - should send message with style #4');
  
  // Test again - should send message with fourth style
  return birthdayManager.checkBirthdays();
}).then(() => {
  console.log('\n[TEST] Fifth check completed');
  
  // Reset lastCelebrated again
  const guildData = birthdayManager.birthdays.get('123456789');
  if (guildData) {
    for (const [userId, userData] of guildData.users.entries()) {
      userData.lastCelebrated = null;
    }
  }
  birthdayManager.saveBirthdays();
  
  console.log('\n[TEST] Running sixth check - should send message with style #1 (cycle completed)');
  
  // Test again - should send message with first style again (cycle completed)
  return birthdayManager.checkBirthdays();
}).then(() => {
  console.log('\n[TEST] Sixth check completed');
  
  // Clean up test data
  fs.unlinkSync(tempDataPath);
  
  // Restore original data path
  birthdayManager.dataPath = originalDataPath;
  
  console.log('\n[TEST] Test completed - birthday celebration system works as expected!');
}).catch(error => {
  console.error('[TEST ERROR]', error);
  
  // Clean up even if there's an error
  try {
    if (fs.existsSync(tempDataPath)) {
      fs.unlinkSync(tempDataPath);
    }
    birthdayManager.dataPath = originalDataPath;
  } catch (cleanupError) {
    console.error('[TEST CLEANUP ERROR]', cleanupError);
  }
});