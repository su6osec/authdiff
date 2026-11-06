package io.github.authdiff.burp.ui;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;
import io.github.authdiff.burp.engine.AuthDiffWorkerPool;
import io.github.authdiff.burp.model.BurpExchangeRecord;
import io.github.authdiff.core.model.AuthDiffFinding;
import io.github.authdiff.core.model.DiffReport;
import io.github.authdiff.core.model.FindingSignal;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.border.TitledBorder;
import java.awt.*;
import java.io.File;
import java.nio.file.Files;
import java.util.List;

/**
 * Main Suite Tab UI component for authdiff in Burp Suite Community Edition.
 */
public final class AuthDiffTab {

    private final MontoyaApi api;
    private final AuthDiffTableModel tableModel;
    private final AuthDiffWorkerPool workerPool;

    private final JPanel rootPanel;
    private final JTextArea attackerHeadersArea;
    private final JTextField allowlistField;
    private final JCheckBox testAnonBox;
    private final JCheckBox safeMethodsBox;
    private final JCheckBox scopeOnlyBox;
    private final JSpinner rateLimitSpinner;
    private final JTable resultsTable;

    private final HttpRequestEditor ownerReqEditor;
    private final HttpResponseEditor ownerResEditor;
    private final HttpRequestEditor attackerReqEditor;
    private final HttpResponseEditor attackerResEditor;
    private final HttpRequestEditor anonReqEditor;
    private final HttpResponseEditor anonResEditor;
    private final JTextArea analysisArea;

    public AuthDiffTab(MontoyaApi api, AuthDiffTableModel tableModel, AuthDiffWorkerPool workerPool) {
        this.api = api;
        this.tableModel = tableModel;
        this.workerPool = workerPool;

        this.rootPanel = new JPanel(new BorderLayout(5, 5));
        this.rootPanel.setBorder(new EmptyBorder(8, 8, 8, 8));

        // Config Panel (Top)
        JPanel topConfigPanel = new JPanel(new GridBagLayout());
        topConfigPanel.setBorder(new TitledBorder("authdiff Configuration & Safety Guardrails"));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.fill = GridBagConstraints.BOTH;
        gbc.insets = new Insets(4, 4, 4, 4);

        // Attacker Headers Area
        attackerHeadersArea = new JTextArea(4, 40);
        attackerHeadersArea.setText("Cookie: session=user_b_cookie_value\nAuthorization: Bearer token_user_b");
        JScrollPane headerScroll = new JScrollPane(attackerHeadersArea);
        headerScroll.setBorder(new TitledBorder("User B (Attacker) Headers / Cookies"));

        gbc.gridx = 0;
        gbc.gridy = 0;
        gbc.gridheight = 3;
        gbc.weightx = 0.5;
        gbc.weighty = 1.0;
        topConfigPanel.add(headerScroll, gbc);

        // Options & Guardrails
        JPanel optionsPanel = new JPanel(new GridLayout(4, 1, 2, 2));
        testAnonBox = new JCheckBox("Test Unauthenticated (Anon)", true);
        safeMethodsBox = new JCheckBox("Replay only safe methods (GET, HEAD, OPTIONS)", true);
        safeMethodsBox.setToolTipText("UNCHECKING THIS PERMITS POST/PUT/DELETE REPLAYS. Proceed with caution on production!");
        scopeOnlyBox = new JCheckBox("Restrict to Target Scope only", true);

        JPanel ratePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 0));
        ratePanel.add(new JLabel("Rate limit (req/s):"));
        rateLimitSpinner = new JSpinner(new SpinnerNumberModel(2.0, 0.2, 50.0, 0.5));
        ratePanel.add(rateLimitSpinner);

        optionsPanel.add(testAnonBox);
        optionsPanel.add(safeMethodsBox);
        optionsPanel.add(scopeOnlyBox);
        optionsPanel.add(ratePanel);

        gbc.gridx = 1;
        gbc.gridy = 0;
        gbc.gridheight = 2;
        gbc.weightx = 0.3;
        topConfigPanel.add(optionsPanel, gbc);

        // Public Allowlist & Action Buttons
        JPanel actionPanel = new JPanel(new BorderLayout(4, 4));
        allowlistField = new JTextField("/api/public/**, /assets/**");
        JPanel allowlistRow = new JPanel(new BorderLayout(4, 4));
        allowlistRow.add(new JLabel("Public Endpoint Allowlist:"), BorderLayout.NORTH);
        allowlistRow.add(allowlistField, BorderLayout.CENTER);
        actionPanel.add(allowlistRow, BorderLayout.NORTH);

        JPanel btnRow = new JPanel(new FlowLayout(FlowLayout.RIGHT, 6, 2));
        JButton clearBtn = new JButton("Clear Results");
        JButton exportJsonBtn = new JButton("Export JSON");
        JButton exportMdBtn = new JButton("Export Markdown");

        btnRow.add(clearBtn);
        btnRow.add(exportJsonBtn);
        btnRow.add(exportMdBtn);
        actionPanel.add(btnRow, BorderLayout.SOUTH);

        gbc.gridx = 2;
        gbc.gridy = 0;
        gbc.gridheight = 2;
        gbc.weightx = 0.2;
        topConfigPanel.add(actionPanel, gbc);

        rootPanel.add(topConfigPanel, BorderLayout.NORTH);

        // Wire Configuration listeners
        Runnable configSync = this::syncConfigToWorker;
        attackerHeadersArea.getDocument().addDocumentListener(new SimpleDocumentListener(configSync));
        allowlistField.getDocument().addDocumentListener(new SimpleDocumentListener(configSync));
        testAnonBox.addActionListener(e -> configSync.run());
        safeMethodsBox.addActionListener(e -> configSync.run());
        scopeOnlyBox.addActionListener(e -> configSync.run());
        rateLimitSpinner.addChangeListener(e -> configSync.run());

        clearBtn.addActionListener(e -> {
            tableModel.clear();
            clearEditors();
        });

        exportJsonBtn.addActionListener(e -> exportReport("JSON"));
        exportMdBtn.addActionListener(e -> exportReport("MARKDOWN"));

        // Results Table (Center)
        resultsTable = new JTable(tableModel);
        resultsTable.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        resultsTable.setDefaultRenderer(io.github.authdiff.core.model.Verdict.class, new VerdictCellRenderer());
        resultsTable.setDefaultRenderer(io.github.authdiff.core.model.ConfidenceScore.class, new VerdictCellRenderer());

        JScrollPane tableScroll = new JScrollPane(resultsTable);

        // Message Editors (Bottom Tabbed Pane)
        ownerReqEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        ownerResEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
        attackerReqEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        attackerResEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);
        anonReqEditor = api.userInterface().createHttpRequestEditor(EditorOptions.READ_ONLY);
        anonResEditor = api.userInterface().createHttpResponseEditor(EditorOptions.READ_ONLY);

        JSplitPane ownerSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, ownerReqEditor.uiComponent(), ownerResEditor.uiComponent());
        ownerSplit.setResizeWeight(0.5);

        JSplitPane attackerSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, attackerReqEditor.uiComponent(), attackerResEditor.uiComponent());
        attackerSplit.setResizeWeight(0.5);

        JSplitPane anonSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, anonReqEditor.uiComponent(), anonResEditor.uiComponent());
        anonSplit.setResizeWeight(0.5);

        analysisArea = new JTextArea();
        analysisArea.setEditable(false);
        analysisArea.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 12));
        JScrollPane analysisScroll = new JScrollPane(analysisArea);

        JTabbedPane viewerTabs = new JTabbedPane();
        viewerTabs.addTab("Owner (Identity A)", ownerSplit);
        viewerTabs.addTab("Attacker (Identity B)", attackerSplit);
        viewerTabs.addTab("Anonymous", anonSplit);
        viewerTabs.addTab("Signals & Analysis", analysisScroll);

        JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, viewerTabs);
        mainSplit.setResizeWeight(0.4);
        rootPanel.add(mainSplit, BorderLayout.CENTER);

        // Row Selection Listener
        resultsTable.getSelectionModel().addListSelectionListener(e -> {
            if (!e.getValueIsAdjusting()) {
                int row = resultsTable.getSelectedRow();
                if (row >= 0) {
                    BurpExchangeRecord record = tableModel.getRecordAt(row);
                    if (record != null) {
                        displayRecord(record);
                    }
                }
            }
        });

        syncConfigToWorker();
    }

    public Component getComponent() {
        return rootPanel;
    }

    private void syncConfigToWorker() {
        double rps = ((Number) rateLimitSpinner.getValue()).doubleValue();
        workerPool.updateConfig(
                attackerHeadersArea.getText(),
                allowlistField.getText(),
                testAnonBox.isSelected(),
                safeMethodsBox.isSelected(),
                scopeOnlyBox.isSelected(),
                rps
        );
    }

    private void displayRecord(BurpExchangeRecord rec) {
        if (rec.ownerExchange() != null) {
            ownerReqEditor.setRequest(rec.ownerExchange().request());
            ownerResEditor.setResponse(rec.ownerExchange().response());
        } else {
            ownerReqEditor.setRequest(null);
            ownerResEditor.setResponse(null);
        }

        if (rec.attackerExchange() != null) {
            attackerReqEditor.setRequest(rec.attackerExchange().request());
            attackerResEditor.setResponse(rec.attackerExchange().response());
        } else {
            attackerReqEditor.setRequest(null);
            attackerResEditor.setResponse(null);
        }

        if (rec.anonExchange() != null) {
            anonReqEditor.setRequest(rec.anonExchange().request());
            anonResEditor.setResponse(rec.anonExchange().response());
        } else {
            anonReqEditor.setRequest(null);
            anonResEditor.setResponse(null);
        }

        // Render explanation & signals
        AuthDiffFinding f = rec.finding();
        StringBuilder sb = new StringBuilder();
        sb.append("VERDICT: ").append(f.verdict().displayName()).append("\n");
        sb.append("CONFIDENCE: ").append(f.confidence().value()).append("% (").append(f.confidence().level()).append(")\n");
        sb.append("ENDPOINT: ").append(f.method()).append(" ").append(f.path()).append("\n");
        sb.append("SUMMARY: ").append(f.humanSummary()).append("\n\n");
        sb.append("EVALUATION SIGNALS:\n");
        for (FindingSignal sig : f.signals()) {
            sb.append("  [").append(sig.category()).append("] ")
                    .append(sig.code()).append(": ")
                    .append(sig.description()).append(" (delta: ")
                    .append(sig.weightDelta()).append(")\n");
        }
        analysisArea.setText(sb.toString());
        analysisArea.setCaretPosition(0);
    }

    private void clearEditors() {
        ownerReqEditor.setRequest(null);
        ownerResEditor.setResponse(null);
        attackerReqEditor.setRequest(null);
        attackerResEditor.setResponse(null);
        anonReqEditor.setRequest(null);
        anonResEditor.setResponse(null);
        analysisArea.setText("");
    }

    private void exportReport(String format) {
        List<BurpExchangeRecord> records = tableModel.getAllRecords();
        if (records.isEmpty()) {
            JOptionPane.showMessageDialog(rootPanel, "No results to export.", "authdiff", JOptionPane.INFORMATION_MESSAGE);
            return;
        }

        JFileChooser chooser = new JFileChooser();
        chooser.setSelectedFile(new File("authdiff-report." + ("JSON".equalsIgnoreCase(format) ? "json" : "md")));
        int choice = chooser.showSaveDialog(rootPanel);
        if (choice == JFileChooser.APPROVE_OPTION) {
            File dest = chooser.getSelectedFile();
            try {
                List<AuthDiffFinding> findings = records.stream().map(BurpExchangeRecord::finding).toList();
                DiffReport report = DiffReport.fromFindings(findings);
                String content;
                if ("JSON".equalsIgnoreCase(format)) {
                    content = io.github.authdiff.core.format.JsonReportFormatter.format(report);
                } else {
                    content = io.github.authdiff.core.format.MarkdownReportFormatter.format(report);
                }
                Files.writeString(dest.toPath(), content);
                JOptionPane.showMessageDialog(rootPanel, "Exported successfully to " + dest.getName(), "authdiff", JOptionPane.INFORMATION_MESSAGE);
            } catch (Exception ex) {
                JOptionPane.showMessageDialog(rootPanel, "Export failed: " + ex.getMessage(), "Error", JOptionPane.ERROR_MESSAGE);
            }
        }
    }

    private record SimpleDocumentListener(Runnable callback) implements javax.swing.event.DocumentListener {
        @Override public void insertUpdate(javax.swing.event.DocumentEvent e) { callback.run(); }
        @Override public void removeUpdate(javax.swing.event.DocumentEvent e) { callback.run(); }
        @Override public void changedUpdate(javax.swing.event.DocumentEvent e) { callback.run(); }
    }
}
