import * as assert from 'assert';
import * as vscode from 'vscode';

describe('SnitchLint VS Code integration', () => {
  it('extension is present and activatable', async () => {
    const ext = vscode.extensions.getExtension('preethivhiremath.snitchlint');
    assert.ok(ext, 'SnitchLint extension should be loaded in test host');
    await ext!.activate();
    assert.strictEqual(ext!.isActive, true);
  });

  it('snitchlint.scan command is registered', async () => {
    const cmds = await vscode.commands.getCommands(true);
    assert.ok(cmds.includes('snitchlint.scan'), 'scan command should be registered');
  });
});
