package io.github.authdiff.burp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import io.github.authdiff.burp.engine.AuthDiffWorkerPool;

import javax.swing.*;
import java.awt.*;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Registers "Send to authdiff" item in Burp Suite context menus (Proxy history, Repeater, Target).
 */
public final class AuthDiffContextMenuProvider implements ContextMenuItemsProvider {

    private final MontoyaApi api;
    private final AuthDiffWorkerPool workerPool;

    public AuthDiffContextMenuProvider(MontoyaApi api, AuthDiffWorkerPool workerPool) {
        this.api = api;
        this.workerPool = workerPool;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        List<HttpRequestResponse> selected = new ArrayList<>();

        if (!event.selectedRequestResponses().isEmpty()) {
            selected.addAll(event.selectedRequestResponses());
        } else if (event.messageEditorRequestResponse().isPresent()) {
            selected.add(event.messageEditorRequestResponse().get().requestResponse());
        }

        if (selected.isEmpty()) {
            return Collections.emptyList();
        }

        JMenuItem menuItem = new JMenuItem(String.format("Send to authdiff (%d request%s)",
                selected.size(), selected.size() > 1 ? "s" : ""));

        menuItem.addActionListener(e -> {
            api.logging().logToOutput(String.format("[authdiff] Enqueued %d request(s) for replay diffing.", selected.size()));
            workerPool.enqueue(selected);
        });

        return List.of(menuItem);
    }
}
