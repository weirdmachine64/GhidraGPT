package ghidragpt;

import ghidra.framework.plugintool.util.PluginPackage;
import resources.ResourceManager;

/**
 * Registers a dedicated "GhidraGPT" plugin package.
 *
 * <p>Ghidra's Configure dialog groups plugins by {@link PluginPackage}, not by
 * their {@code category}. Without a registered package matching the plugin's
 * {@code packageName}, Ghidra falls back to the "Miscellaneous" stub (and logs
 * a "Can't find plugin package for GhidraGPT" warning). Declaring this package
 * gives the plugin its own section in {@code File -> Configure} and removes the
 * warning.
 *
 * <p>{@code PluginPackage} is a Ghidra {@code ExtensionPoint}, so this class is
 * discovered automatically; it only needs a public no-arg constructor. The
 * {@link #NAME} must match {@code packageName} in {@link GhidraGPTPlugin}.
 */
public class GhidraGPTPluginPackage extends PluginPackage {

    public static final String NAME = "GhidraGPT";

    public GhidraGPTPluginPackage() {
        super(NAME, ResourceManager.getDefaultIcon(),
              "LLM-assisted reverse engineering: explain, rewrite, and audit decompiled functions.");
    }
}
