package ghidragpt.ui;

import javax.swing.*;
import javax.swing.text.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;

/**
 * Dedicated console for GhidraGPT output
 */
public class Console extends JPanel {
    
    private final JTextPane textPane;
    private final StyledDocument document;
    private final JScrollPane scrollPane;
    private final SimpleDateFormat timeFormat;
    
    // Text styles
    private Style timestampStyle;
    private Style functionStyle;
    private Style resultStyle;
    private Style errorStyle;
    
    public Console() {
        setLayout(new BorderLayout());
        
        // Initialize components with enhanced styling
        textPane = new JTextPane();
        textPane.setEditable(false);
        
        // Use a big, clear, readable font
        Font consoleFont = new Font("Arial", Font.PLAIN, 14);
        
        textPane.setFont(consoleFont);
        textPane.setBackground(new Color(24, 24, 24)); // Darker, more professional background
        textPane.setForeground(new Color(220, 220, 220)); // Light text
        textPane.setBorder(BorderFactory.createEmptyBorder(10, 15, 10, 15)); // Padding
        
        // Enable antialiasing for better emoji and text rendering
        textPane.putClientProperty("awt.useSystemAAFontSettings", "on");
        textPane.putClientProperty("swing.aatext", true);
        
        document = textPane.getStyledDocument();
        scrollPane = new JScrollPane(textPane);
        scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
        scrollPane.setBorder(BorderFactory.createEmptyBorder()); // Remove default border
        scrollPane.getViewport().setBackground(new Color(24, 24, 24));
        
        timeFormat = new SimpleDateFormat("HH:mm:ss");
        
        // Initialize styles
        initializeStyles();
        
        // Create toolbar
        JPanel toolbarPanel = createToolbar();
        
        // Layout
        add(toolbarPanel, BorderLayout.NORTH);
        add(scrollPane, BorderLayout.CENTER);
        
        // Welcome message with style
        appendMessage("🚀 GhidraGPT", "Console initialized. AI analysis results will appear here.", MessageType.HEADER);
    }
    
    private void initializeStyles() {
        // Timestamp style - subtle blue-gray
        timestampStyle = textPane.addStyle("timestamp", null);
        StyleConstants.setForeground(timestampStyle, new Color(108, 153, 187));
        StyleConstants.setBold(timestampStyle, false);
        StyleConstants.setItalic(timestampStyle, true);
        
        // Function name style - bright cyan for visibility
        functionStyle = textPane.addStyle("function", null);
        StyleConstants.setForeground(functionStyle, new Color(102, 217, 239));
        StyleConstants.setBold(functionStyle, true);
        
        // Result style - clean white with slight warmth
        resultStyle = textPane.addStyle("result", null);
        StyleConstants.setForeground(resultStyle, new Color(230, 230, 230));
        StyleConstants.setBold(resultStyle, false);
        
        // Error style - bright red for errors
        errorStyle = textPane.addStyle("error", null);
        StyleConstants.setForeground(errorStyle, new Color(255, 92, 87));
        StyleConstants.setBold(errorStyle, true);
        
        // Success/info style - soft green
        Style successStyle = textPane.addStyle("success", null);
        StyleConstants.setForeground(successStyle, new Color(152, 195, 121));
        StyleConstants.setBold(successStyle, false);
        
        // Warning style - golden yellow
        Style warningStyle = textPane.addStyle("warning", null);
        StyleConstants.setForeground(warningStyle, new Color(229, 192, 123));
        StyleConstants.setBold(warningStyle, true);
        
        // Header style for analysis headers
        Style headerStyle = textPane.addStyle("header", null);
        StyleConstants.setForeground(headerStyle, new Color(198, 120, 221));
        StyleConstants.setBold(headerStyle, true);
        StyleConstants.setFontSize(headerStyle, 14);
    }
    
    private JPanel createToolbar() {
        JPanel toolbar = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 2));
        toolbar.setBackground(new Color(32, 32, 32));
        toolbar.setBorder(BorderFactory.createEmptyBorder(2, 10, 2, 10));
        
        // Style buttons with modern flat design
        JButton clearButton = createStyledButton("🗑️ Clear", new Color(255, 92, 87));
        clearButton.setPreferredSize(new Dimension(85, 24));
        clearButton.addActionListener(e -> clearConsole());
        
        JButton copyButton = createStyledButton("📋 Copy", new Color(102, 217, 239));
        copyButton.setPreferredSize(new Dimension(85, 24));
        copyButton.addActionListener(e -> copyToClipboard());
        
        // Add a title label
        JLabel titleLabel = new JLabel("🤖 GhidraGPT Console");
        titleLabel.setForeground(new Color(198, 120, 221));
        titleLabel.setFont(titleLabel.getFont().deriveFont(Font.BOLD, 12f));
        
        toolbar.add(titleLabel);
        toolbar.add(Box.createHorizontalStrut(20));
        toolbar.add(clearButton);
        toolbar.add(Box.createHorizontalStrut(5));
        toolbar.add(copyButton);
        
        return toolbar;
    }
    
    private JButton createStyledButton(String text, Color accentColor) {
        JButton button = new JButton(text);
        button.setBackground(new Color(45, 45, 45));
        button.setForeground(accentColor);
        button.setBorder(BorderFactory.createCompoundBorder(
            BorderFactory.createLineBorder(accentColor.darker(), 1),
            BorderFactory.createEmptyBorder(4, 8, 4, 8)
        ));
        button.setFocusPainted(false);
        button.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        
        // Hover effect
        button.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseEntered(java.awt.event.MouseEvent evt) {
                button.setBackground(accentColor.darker().darker());
            }
            
            @Override
            public void mouseExited(java.awt.event.MouseEvent evt) {
                button.setBackground(new Color(45, 45, 45));
            }
        });
        
        return button;
    }
    
    public enum MessageType {
        INFO, SUCCESS, ERROR, FUNCTION, RESULT, WARNING, HEADER
    }
    
    public void appendMessage(String functionName, String message, MessageType type) {
        SwingUtilities.invokeLater(() -> {
            try {
                String timestamp = timeFormat.format(new Date());
                
                // Add timestamp
                document.insertString(document.getLength(), "[" + timestamp + "] ", timestampStyle);
                
                // Add function name if provided
                if (functionName != null && !functionName.isEmpty()) {
                    document.insertString(document.getLength(), functionName + ": ", functionStyle);
                }
                
                // Add message with appropriate style
                Style messageStyle;
                switch (type) {
                    case ERROR:
                        messageStyle = errorStyle;
                        break;
                    case FUNCTION:
                        messageStyle = functionStyle;
                        break;
                    case SUCCESS:
                        messageStyle = textPane.getStyle("success");
                        break;
                    case WARNING:
                        messageStyle = textPane.getStyle("warning");
                        break;
                    case HEADER:
                        messageStyle = textPane.getStyle("header");
                        break;
                    default:
                        messageStyle = resultStyle;
                        break;
                }
                
                document.insertString(document.getLength(), message + "\n\n", messageStyle);
                
                // Auto-scroll to bottom
                textPane.setCaretPosition(document.getLength());
                
            } catch (BadLocationException e) {
                // Fallback to simple append
                textPane.setText(textPane.getText() + "\n" + message);
            }
        });
    }
    
    public void appendAnalysisResult(String functionName, String operation, String result) {
        // Create a visually appealing separator
        String separator = "═".repeat(60);
        appendMessage(functionName, operation + "\n" + separator + "\n" + result, MessageType.RESULT);
    }
    
    public void appendError(String functionName, String error) {
        appendMessage(functionName, "ERROR: " + error, MessageType.ERROR);
    }
    
    public void appendInfo(String message) {
        appendMessage(null, message, MessageType.INFO);
    }
    
    /**
     * Print standardized analysis start header with visual enhancements
     */
    public void printAnalysisHeader(String operation, String functionName, String provider, String model, int promptLength) {
        try {
            // Create a visually appealing header with proper padding
            String headerTitle = operation + " Started";
            String header = "\n╔" + "═".repeat(58) + "╗\n" +
                           "║ ⚡ " + centerText(headerTitle, 52) + " ║\n" +
                           "╠" + "═".repeat(58) + "╣\n" +
                           "║ ► Function:  " + padRight(functionName, 43) + " ║\n" +
                           "║ ◆ Provider:  " + padRight(provider, 43) + " ║\n" +
                           "║ ● Model:     " + padRight(model, 43) + " ║\n" +
                           "║ ■ Size:      " + padRight(promptLength + " chars", 43) + " ║\n" +
                           "╚" + "═".repeat(58) + "╝\n";
            
            document.insertString(document.getLength(), header, textPane.getStyle("header"));
            textPane.setCaretPosition(document.getLength());
            scrollPane.getVerticalScrollBar().setValue(scrollPane.getVerticalScrollBar().getMaximum());
        } catch (BadLocationException e) {
            // Fallback to simple message
            appendMessage("Analysis", operation + " started for " + functionName, MessageType.INFO);
        }
    }
    
    // Helper methods for text formatting
    private String centerText(String text, int width) {
        if (text.length() >= width) return text.substring(0, width);
        int padding = (width - text.length()) / 2;
        String leftPad = " ".repeat(padding);
        String rightPad = " ".repeat(width - text.length() - padding);
        return leftPad + text + rightPad;
    }
    
    private String padRight(String text, int width) {
        if (text.length() >= width) return text.substring(0, width);
        return text + " ".repeat(width - text.length());
    }
    
    /**
     * Print stream header (called on first response)
     */
    public void printStreamHeader() {
        try {
            String header = "\n┌─ ▲ AI Response Stream ─────────────────────────────────┐\n";
            document.insertString(document.getLength(), header, textPane.getStyle("success"));
            textPane.setCaretPosition(document.getLength());
        } catch (BadLocationException e) {
            appendMessage("Stream", "AI Response starting...", MessageType.INFO);
        }
    }
    
    /**
     * Print stream completion message
     */
    public void printStreamComplete(String operation, long duration, int responseLength) {
        try {
            String footer = "\n└─────────────────────────────────────────────────────────┘\n" +
                           "√ " + operation + " completed in " + duration + "ms (" + responseLength + " characters)\n" +
                           "═".repeat(65) + "\n";
            document.insertString(document.getLength(), footer, textPane.getStyle("success"));
            textPane.setCaretPosition(document.getLength());
            scrollPane.getVerticalScrollBar().setValue(scrollPane.getVerticalScrollBar().getMaximum());
        } catch (BadLocationException e) {
            appendMessage("Stream", operation + " completed in " + duration + "ms", MessageType.SUCCESS);
        }
    }
    
    /**
     * Print stream error message
     */
    public void printStreamError(String operation, String error) {
        try {
            String errorMsg = "\n└─ X Error ──────────────────────────────────────────────┘\n" +
                             "X " + operation + " failed: " + error + "\n";
            document.insertString(document.getLength(), errorMsg, textPane.getStyle("error"));
            textPane.setCaretPosition(document.getLength());
            scrollPane.getVerticalScrollBar().setValue(scrollPane.getVerticalScrollBar().getMaximum());
        } catch (BadLocationException e) {
            appendMessage("Stream Error", operation + " failed: " + error, MessageType.ERROR);
        }
    }
    
    /**
     * Append streaming text content without timestamp (for real-time streaming)
     */
    public void appendStreamingText(String text) {
        SwingUtilities.invokeLater(() -> {
            try {
                document.insertString(document.getLength(), text, resultStyle);
                textPane.setCaretPosition(document.getLength());
                scrollPane.getVerticalScrollBar().setValue(scrollPane.getVerticalScrollBar().getMaximum());
            } catch (BadLocationException e) {
                // Fallback to simple append
                textPane.setText(textPane.getText() + text);
            }
        });
    }
    
    /**
     * Print suggestion summary with per-line coloring (green for OK, red for FAIL)
     */
    public void printSuggestionSummary(String functionName, List<String[]> lines) {
        SwingUtilities.invokeLater(() -> {
            try {
                String timestamp = timeFormat.format(new Date());
                document.insertString(document.getLength(), "[" + timestamp + "] ", timestampStyle);
                document.insertString(document.getLength(), functionName + ": ", functionStyle);
                String separator = "-".repeat(60) + "\n";
                document.insertString(document.getLength(), "\nSuggestion Summary:\n", resultStyle);
                document.insertString(document.getLength(), separator, resultStyle);
                for (String[] line : lines) {
                    // line[0] = "OK" or "FAIL", line[1] = text
                    Style style = "OK".equals(line[0]) ? textPane.getStyle("success") : errorStyle;
                    document.insertString(document.getLength(), line[1] + "\n", style);
                }
                document.insertString(document.getLength(), separator + "\n", resultStyle);
                textPane.setCaretPosition(document.getLength());
            } catch (BadLocationException e) {
                // fallback
            }
        });
    }

    private void clearConsole() {
        textPane.setText("");
        appendMessage("🧹 System", "Console cleared.", MessageType.SUCCESS);
    }
    
    private void copyToClipboard() {
        textPane.selectAll();
        textPane.copy();
        textPane.setCaretPosition(document.getLength());
        appendMessage("📋 System", "Console content copied to clipboard!", MessageType.SUCCESS);
    }
}
