package io.github.authdiff.burp.ui;

import io.github.authdiff.core.model.ConfidenceScore;
import io.github.authdiff.core.model.Verdict;

import javax.swing.*;
import javax.swing.table.DefaultTableCellRenderer;
import java.awt.*;

/**
 * Custom table cell renderer that visually distinguishes verdicts and confidence levels.
 */
public final class VerdictCellRenderer extends DefaultTableCellRenderer {

    private static final long serialVersionUID = 1L;

    private static final Color RED_BG = new Color(255, 230, 230);
    private static final Color RED_TEXT = new Color(180, 0, 0);

    private static final Color GREEN_BG = new Color(230, 255, 230);
    private static final Color GREEN_TEXT = new Color(0, 120, 0);

    private static final Color YELLOW_BG = new Color(255, 255, 220);
    private static final Color YELLOW_TEXT = new Color(160, 110, 0);

    @Override
    public Component getTableCellRendererComponent(JTable table, Object value,
                                                   boolean isSelected, boolean hasFocus,
                                                   int row, int column) {
        Component c = super.getTableCellRendererComponent(table, value, isSelected, hasFocus, row, column);

        if (isSelected) {
            return c;
        }

        if (value instanceof Verdict verdict) {
            setText(verdict.name());
            setFont(getFont().deriveFont(Font.BOLD));
            switch (verdict) {
                case LIKELY_IDOR_BOLA, MISSING_AUTHENTICATION -> {
                    setBackground(RED_BG);
                    setForeground(RED_TEXT);
                }
                case ENFORCED -> {
                    setBackground(GREEN_BG);
                    setForeground(GREEN_TEXT);
                }
                case INCONCLUSIVE -> {
                    setBackground(YELLOW_BG);
                    setForeground(YELLOW_TEXT);
                }
            }
        } else if (value instanceof ConfidenceScore conf) {
            setText(conf.value() + "% (" + conf.level() + ")");
            switch (conf.level()) {
                case HIGH -> {
                    setBackground(RED_BG);
                    setForeground(RED_TEXT);
                }
                case MEDIUM -> {
                    setBackground(YELLOW_BG);
                    setForeground(YELLOW_TEXT);
                }
                case LOW -> {
                    setBackground(table.getBackground());
                    setForeground(table.getForeground());
                }
            }
        } else {
            setBackground(table.getBackground());
            setForeground(table.getForeground());
        }

        return c;
    }
}
