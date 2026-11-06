package io.github.authdiff.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import io.github.authdiff.burp.engine.AuthDiffWorkerPool;
import io.github.authdiff.burp.ui.AuthDiffTab;
import io.github.authdiff.burp.ui.AuthDiffTableModel;

/**
 * Main Burp Suite extension entrypoint for authdiff.
 * Fully compatible with Burp Suite Community Edition (no Pro-only APIs used).
 */
public final class AuthDiffExtension implements BurpExtension {

    private static final String BANNER = """
            ======================================================================
               authdiff - Broken Access Control & IDOR/BOLA Detection Extension
            ======================================================================
            Pinned Montoya API: 2026.7
            Notice: Use only against systems you have explicit permission to test.
            ======================================================================
            """;

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("authdiff");
        api.logging().logToOutput(BANNER);

        AuthDiffTableModel tableModel = new AuthDiffTableModel();
        AuthDiffWorkerPool workerPool = new AuthDiffWorkerPool(api, tableModel);
        AuthDiffTab suiteTab = new AuthDiffTab(api, tableModel, workerPool);
        AuthDiffContextMenuProvider contextMenuProvider = new AuthDiffContextMenuProvider(api, workerPool);

        // Register Suite Tab
        api.userInterface().registerSuiteTab("authdiff", suiteTab.getComponent());

        // Register Context Menu Provider (Proxy, Repeater, Target)
        api.userInterface().registerContextMenuItemsProvider(contextMenuProvider);

        // Register Unload Handler to cleanly cancel pending work and shutdown thread pools
        api.extension().registerUnloadingHandler(() -> {
            api.logging().logToOutput("[authdiff] Extension unloaded. Shutting down worker thread pool...");
            workerPool.shutdown();
        });

        api.logging().logToOutput("[authdiff] Extension initialized successfully in Suite tab 'authdiff'.");
    }
}
