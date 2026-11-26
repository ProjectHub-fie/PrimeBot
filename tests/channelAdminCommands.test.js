// Channel admin commands ($cp / $rm #channel / $mkdir / $hmkdir + /channel).
// Pure unit tests with a fake guild — no Discord connection.

const { test } = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { ChannelType } = require('discord.js');

const ROOT = path.join(__dirname, '..');
const admin = require('../utils/channelAdmin');

function fakeChannel({ id, name, type = ChannelType.GuildText, parentId = null, deletable = true }) {
    const channel = {
        id,
        name,
        type,
        parentId,
        deletable,
        toString() { return `<#${id}>`; },
        delete: async () => { channel.deleted = true; },
    };
    return channel;
}

function fakeGuild(channels = []) {
    const map = new Map(channels.map(c => [c.id, c]));
    const guild = {
        id: 'guild-1',
        roles: { everyone: { id: 'everyone-role' } },
        created: [],
        channels: {
            cache: map,
            create: async (opts) => {
                const channel = fakeChannel({
                    id: `created-${guild.created.length + 1}`,
                    name: opts.name,
                    type: opts.type,
                    parentId: opts.parent || null,
                });
                channel.reason = opts.reason;
                guild.created.push({ opts, channel });
                map.set(channel.id, channel);
                return channel;
            },
        },
    };
    return guild;
}

test('channel names are sanitised for Discord', () => {
    assert.equal(admin.sanitizeName('General Chat'), 'general-chat');
    assert.equal(admin.sanitizeName('  #Announcements!!  '), 'announcements');
    assert.equal(admin.sanitizeName('a   b___c'), 'a-b___c');
    assert.equal(admin.sanitizeName('***'), 'new-channel');
    assert.equal(admin.sanitizeName(''), 'new-channel');
    assert.equal(admin.sanitizeName('x'.repeat(150)).length, admin.NAME_MAX);
});

test('mentions and ids resolve inside the guild only', () => {
    const text = fakeChannel({ id: '111111111111111111', name: 'general' });
    const category = fakeChannel({ id: '222222222222222222', name: 'Info', type: ChannelType.GuildCategory });
    const guild = fakeGuild([text, category]);

    assert.equal(admin.findChannel(guild, '<#111111111111111111>'), text);
    assert.equal(admin.findChannel(guild, '111111111111111111'), text);
    assert.equal(admin.findChannel(guild, 'GENERAL'), text);
    assert.equal(admin.findChannel(guild, 'gen'), text);
    assert.equal(admin.findChannel(guild, '<#999999999999999999>'), null, 'unknown ids never resolve');

    assert.equal(admin.findCategory(guild, 'info'), category);
    assert.equal(admin.findCategory(guild, '<#222222222222222222>'), category);
    assert.equal(admin.findCategory(guild, 'general'), null, 'a text channel is not a category');
});

test('$cp creates a text channel, optionally inside a category', async () => {
    const category = fakeChannel({ id: '222222222222222222', name: 'Info', type: ChannelType.GuildCategory });
    const guild = fakeGuild([category]);

    const plain = await admin.createTextChannel(guild, 'General Chat', null, { invokerId: 'u1' });
    assert.equal(plain.ok, true);
    assert.equal(guild.created[0].opts.name, 'general-chat');
    assert.equal(guild.created[0].opts.type, ChannelType.GuildText);
    assert.equal(guild.created[0].opts.parent, undefined);
    assert.match(guild.created[0].opts.reason, /u1/);

    const nested = await admin.createTextChannel(guild, 'rules', '<#222222222222222222>', { invokerId: 'u1' });
    assert.equal(nested.ok, true);
    assert.equal(guild.created[1].opts.parent, category.id);
    assert.match(nested.text, /Info/);

    const missing = await admin.createTextChannel(guild, 'rules', '<#999999999999999999>', { invokerId: 'u1' });
    assert.equal(missing.ok, false);
    assert.match(missing.text, /could not find a category/);
    assert.equal(guild.created.length, 2, 'a failed lookup must not create anything');
});

test('$cp / $cv create public or private channels', async () => {
    const guild = fakeGuild([]);

    const publicText = await admin.createTextChannel(guild, 'general', null, { invokerId: 'u1', visibility: 'public' });
    assert.equal(publicText.ok, true);
    assert.equal(guild.created[0].opts.type, ChannelType.GuildText);
    assert.equal(guild.created[0].opts.permissionOverwrites, undefined);
    assert.doesNotMatch(publicText.text, /private/);

    const privateText = await admin.createTextChannel(guild, 'staff', null, { invokerId: 'u1', visibility: 'private' });
    assert.equal(privateText.ok, true);
    assert.deepEqual(guild.created[1].opts.permissionOverwrites, [
        { id: 'everyone-role', deny: ['ViewChannel'] },
    ]);
    assert.match(privateText.text, /private channel/);

    const publicVoice = await admin.createVoiceChannel(guild, 'Lounge', null, { invokerId: 'u1', visibility: 'public' });
    assert.equal(publicVoice.ok, true);
    assert.equal(guild.created[2].opts.type, ChannelType.GuildVoice);
    assert.equal(guild.created[2].opts.name, 'lounge');
    assert.equal(guild.created[2].opts.permissionOverwrites, undefined);

    const privateVoice = await admin.createVoiceChannel(guild, 'Admin VC', null, { invokerId: 'u1', visibility: 'private' });
    assert.equal(privateVoice.ok, true);
    assert.equal(guild.created[3].opts.type, ChannelType.GuildVoice);
    assert.deepEqual(guild.created[3].opts.permissionOverwrites, [
        { id: 'everyone-role', deny: ['ViewChannel'] },
    ]);
    assert.match(privateVoice.text, /private voice channel/);
    assert.match(guild.created[3].opts.reason, /\(cv\)/);
});

test('visibility words are parsed with common synonyms', () => {
    assert.equal(admin.parseVisibility('private'), 'private');
    assert.equal(admin.parseVisibility('PRIV'), 'private');
    assert.equal(admin.parseVisibility('hidden'), 'private');
    assert.equal(admin.parseVisibility('public'), 'public');
    assert.equal(admin.parseVisibility('pub'), 'public');
    assert.equal(admin.parseVisibility('open'), 'public');
    assert.equal(admin.parseVisibility('general'), null);
    assert.equal(admin.parseVisibility(''), null);
});

test('$rm deletes a channel but refuses the current one, categories and undeletable channels', async () => {
    const current = fakeChannel({ id: '111111111111111111', name: 'general' });
    const other = fakeChannel({ id: '333333333333333333', name: 'old-chat' });
    const locked = fakeChannel({ id: '444444444444444444', name: 'locked', deletable: false });
    const category = fakeChannel({ id: '222222222222222222', name: 'Info', type: ChannelType.GuildCategory });
    const guild = fakeGuild([current, other, locked, category]);

    const ok = await admin.deleteChannel(guild, '<#333333333333333333>', { invokerId: 'u1', currentChannelId: current.id });
    assert.equal(ok.ok, true);
    assert.equal(other.deleted, true);
    assert.match(ok.text, /old-chat/);

    const self = await admin.deleteChannel(guild, current.id, { invokerId: 'u1', currentChannelId: current.id });
    assert.equal(self.ok, false);
    assert.equal(current.deleted, undefined);

    const cat = await admin.deleteChannel(guild, '<#222222222222222222>', { invokerId: 'u1' });
    assert.equal(cat.ok, false);
    assert.match(cat.text, /hmkdir/);

    const noPerm = await admin.deleteChannel(guild, locked.id, { invokerId: 'u1' });
    assert.equal(noPerm.ok, false);
    assert.equal(locked.deleted, undefined);

    const unknown = await admin.deleteChannel(guild, 'nope', { invokerId: 'u1' });
    assert.equal(unknown.ok, false);
});

test('$mkdir and $hmkdir manage categories without deleting their channels', async () => {
    const child = fakeChannel({ id: '555555555555555555', name: 'rules', parentId: '222222222222222222' });
    const category = fakeChannel({ id: '222222222222222222', name: 'Info', type: ChannelType.GuildCategory });
    const guild = fakeGuild([child, category]);

    const made = await admin.createCategory(guild, 'Events', { invokerId: 'u1' });
    assert.equal(made.ok, true);
    assert.equal(guild.created[0].opts.type, ChannelType.GuildCategory);
    assert.equal(guild.created[0].opts.name, 'events');

    const removed = await admin.deleteCategory(guild, 'info', { invokerId: 'u1' });
    assert.equal(removed.ok, true);
    assert.equal(category.deleted, true);
    assert.match(removed.text, /1 channel moved out/);
    assert.equal(child.deleted, undefined, 'children are never deleted with the category');

    const notACategory = await admin.deleteCategory(guild, 'rules', { invokerId: 'u1' });
    assert.equal(notACategory.ok, false);
});

test('the prefix switch wires cp / rm / mkdir / hmkdir', () => {
    const src = fs.readFileSync(path.join(ROOT, 'events/messageCreate.js'), 'utf8');
    for (const name of ['cp', 'cv', 'mkdir', 'hmkdir']) {
        assert.match(src, new RegExp(`case "${name}":`), `missing case "${name}"`);
    }
    assert.match(src, /channelAdmin\.deleteChannel\(message\.guild/);
    assert.match(src, /channelAdmin\.createTextChannel\(message\.guild/);
    assert.match(src, /channelAdmin\.createVoiceChannel\(message\.guild/);
    assert.match(src, /channelAdmin\.parseVisibility/);
    assert.match(src, /channelAdmin\.createCategory\(message\.guild/);
    assert.match(src, /channelAdmin\.deleteCategory\(message\.guild/);
    assert.match(src, /ManageChannels/);
});

test('the help menu lists the channel commands in the Extra category', () => {
    const help = require('../utils/prefixHelp');
    assert.ok(help.CATEGORY_ORDER.includes('extra'), 'Extra category missing from the menu');
    const extraText = help.categoryText('extra');
    for (const name of ['cp', 'cv', 'mkdir', 'hmkdir']) {
        assert.ok(extraText.includes(name), `Extra help missing ${name}: ${extraText}`);
    }
    // rm (delete/rename) stays in Administration.
    const adminText = help.categoryText('admin');
    assert.ok(adminText.includes('rm'), `admin help missing rm: ${adminText}`);
    assert.ok(!adminText.includes('cp'), 'cp moved out of Administration');

    const extraCat = help.CATALOG.extra.commands;
    const cp = extraCat.find(c => c.names[0] === 'cp');
    assert.ok(cp, 'cp entry missing');
    assert.match(cp.desc, /Create a text channel/);
    const hm = extraCat.find(c => c.names[0] === 'hmkdir');
    assert.ok(hm.names.includes('rmdir'), 'hmkdir should also answer to rmdir');
    const cv = extraCat.find(c => c.names[0] === 'cv');
    assert.ok(cv, 'cv entry missing');
    assert.match(cv.args, /private\|public/);
    assert.match(cv.desc, /voice channel/);
    // Categories are not #-prefixed in Discord, so help args must not show '#category'.
    assert.doesNotMatch(cv.args, /#/);
    assert.doesNotMatch(cp.args, /#/);
    assert.doesNotMatch(hm.args, /#/);
});

test('the /channel slash group mirrors the prefix commands', () => {
    const command = require('../commands/channel');
    assert.equal(command.data.name, 'channel');
    const subs = command.data.options.map(o => o.name);
    assert.deepEqual(subs, ['create', 'delete', 'category-create', 'category-delete']);
    const createOpts = command.data.options.find(o => o.name === 'create').options.map(o => o.name);
    assert.deepEqual(createOpts, ['name', 'type', 'visibility', 'category']);
    assert.ok(command.data.default_member_permissions !== undefined);
});

test('the docs page documents cp / mkdir / hmkdir and the new rm behaviour', () => {
    const { buildCommandDocs } = require('../dashboard/commandDocs');
    const docs = buildCommandDocs();
    const byName = new Map(docs.commands.map(c => [c.name, c]));
    for (const name of ['cp', 'cv', 'mkdir', 'hmkdir', 'rm']) {
        assert.ok(byName.has(name), `${name} missing from /docs`);
    }
    assert.match(byName.get('cp').description, /public or private/);
    assert.match(byName.get('cv').description, /voice channel/);
    assert.match(byName.get('rm').description, /deletes the channel/);
});

test('beta commands are marked with the beta tag in the help menu', () => {
    const help = require('../utils/prefixHelp');
    assert.equal(help.hasBetaCommands(), true);
    assert.match(help.categoryText('leveling'), /🧪/);
    assert.match(help.mainMenuText(), /🧪 = beta feature/);
    // Non-beta entries are not tagged.
    assert.doesNotMatch(help.categoryText('admin'), /🧪/);
});

test('cp / cv accept a plain category name (no # prefix)', async () => {
    const category = fakeChannel({ id: '222222222222222222', name: 'Staff Area', type: ChannelType.GuildCategory });
    const guild = fakeGuild([category]);

    const byName = await admin.createTextChannel(guild, 'private-log', 'staff area', { invokerId: 'u1', visibility: 'private' });
    assert.equal(byName.ok, true);
    assert.equal(guild.created[0].opts.parent, category.id);
    assert.match(byName.text, /Staff Area/);

    const voice = await admin.createVoiceChannel(guild, 'meeting', 'Staff Area', { invokerId: 'u1' });
    assert.equal(voice.ok, true);
    assert.equal(guild.created[1].opts.type, ChannelType.GuildVoice);
    assert.equal(guild.created[1].opts.parent, category.id);
});
