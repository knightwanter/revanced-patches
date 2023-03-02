package app.revanced.patches.youtube.misc.fix.spoof.patch

import app.revanced.patcher.annotation.Description
import app.revanced.patcher.annotation.Name
import app.revanced.patcher.annotation.Version
import app.revanced.patcher.data.BytecodeContext
import app.revanced.patcher.extensions.addInstruction
import app.revanced.patcher.extensions.instruction
import app.revanced.patcher.patch.BytecodePatch
import app.revanced.patcher.patch.PatchResult
import app.revanced.patcher.patch.PatchResultSuccess
import app.revanced.patcher.patch.annotations.Patch
import app.revanced.patches.youtube.misc.fix.spoof.annotations.ClientSpoofCompatibility
import app.revanced.patches.youtube.misc.fix.spoof.fingerprints.UserAgentHeaderBuilderFingerprint
import org.jf.dexlib2.iface.instruction.FiveRegisterInstruction

@Patch
@Name("client-spoof")
@Description("Spoofs the YouTube or Vanced client to prevent playback issues.")
@ClientSpoofCompatibility
@Version("0.0.2")
class ClientSpoofPatch : BytecodePatch(listOf(UserAgentHeaderBuilderFingerprint)) {

    override fun execute(context: BytecodeContext): PatchResult {
        val fingerprint = UserAgentHeaderBuilderFingerprint.result ?: return PatchResultSuccess()

        val method = fingerprint.mutableMethod
        val insertIndex = fingerprint.scanResult.patternScanResult?.endIndex ?: return PatchResultSuccess()

        val packageNameRegister = (method.instruction(insertIndex) as? FiveRegisterInstruction)?.registerD ?: return PatchResultSuccess()
        method.addInstruction(insertIndex, "const-string v$packageNameRegister, \"com.google.android.youtube\"")

        return PatchResultSuccess()
    }
}
