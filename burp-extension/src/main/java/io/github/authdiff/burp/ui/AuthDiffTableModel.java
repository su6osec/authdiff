package io.github.authdiff.burp.ui;

import io.github.authdiff.burp.model.BurpExchangeRecord;
import io.github.authdiff.core.model.AuthDiffFinding;

import javax.swing.table.AbstractTableModel;
import java.util.ArrayList;
import java.util.List;

/**
 * Table model for displaying classified findings in Burp Suite UI.
 */
@SuppressWarnings("serial")
public final class AuthDiffTableModel extends AbstractTableModel {

    private static final long serialVersionUID = 1L;

    private static final String[] COLUMNS = {
            "#", "Method", "URL", "Path", "Object ID", "Status (A/B/?)", "Sim (B)", "Verdict", "Confidence"
    };

    private final List<BurpExchangeRecord> records = new ArrayList<>();

    public synchronized void addRecord(BurpExchangeRecord record) {
        records.add(record);
        int row = records.size() - 1;
        fireTableRowsInserted(row, row);
    }

    public synchronized void clear() {
        records.clear();
        fireTableDataChanged();
    }

    public synchronized BurpExchangeRecord getRecordAt(int row) {
        if (row >= 0 && row < records.size()) {
            return records.get(row);
        }
        return null;
    }

    public synchronized List<BurpExchangeRecord> getAllRecords() {
        return new ArrayList<>(records);
    }

    @Override
    public int getRowCount() {
        return records.size();
    }

    @Override
    public int getColumnCount() {
        return COLUMNS.length;
    }

    @Override
    public String getColumnName(int column) {
        return COLUMNS[column];
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        BurpExchangeRecord record = getRecordAt(rowIndex);
        if (record == null) return null;

        AuthDiffFinding f = record.finding();
        return switch (columnIndex) {
            case 0 -> record.index();
            case 1 -> f.method();
            case 2 -> f.url();
            case 3 -> f.path();
            case 4 -> f.primaryIdentifierString();
            case 5 -> {
                String anon = f.anonStatusCode().map(String::valueOf).orElse("-");
                yield String.format("%d / %d / %s", f.ownerStatusCode(), f.attackerStatusCode(), anon);
            }
            case 6 -> String.format("%.1f%%", f.attackerSimilarity() * 100.0);
            case 7 -> f.verdict();
            case 8 -> f.confidence();
            default -> null;
        };
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        return switch (columnIndex) {
            case 0 -> Integer.class;
            case 7 -> io.github.authdiff.core.model.Verdict.class;
            case 8 -> io.github.authdiff.core.model.ConfidenceScore.class;
            default -> String.class;
        };
    }
}
