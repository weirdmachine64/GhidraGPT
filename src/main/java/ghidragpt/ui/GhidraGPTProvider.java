package ghidragpt.ui;

import docking.ActionContext;
import docking.ComponentProvider;
import docking.WindowPosition;
import docking.action.DockingAction;
import docking.action.MenuData;
// import docking.action.ToolBarData;
import ghidra.app.context.ListingActionContext;
import ghidra.app.context.ProgramActionContext;
import ghidra.app.plugin.core.decompile.DecompilerActionContext;
import ghidra.framework.plugintool.Plugin;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.util.HelpLocation;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import ghidragpt.GhidraGPTPlugin;
import ghidragpt.service.GhidraGPTService;
// import resources.Icons;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

/**
 * Main UI provider for the GhidraGPT plugin
 */
public class GhidraGPTProvider extends ComponentProvider {

    private final GhidraGPTPlugin plugin;
    private final JPanel mainPanel;
    private final ConfigurationPanel configPanel;
    private final Console console;
    private final JTabbedPane tabbedPane;
    private GhidraGPTService gptService;
    private Program currentProgram;

    public GhidraGPTProvider(GhidraGPTPlugin plugin, String name) {
        super(plugin.getTool(), name, name);
        this.plugin = plugin;

        // Configure docking properties
        setDefaultWindowPosition(WindowPosition.BOTTOM);
        setTransient();

        // Initialize UI components
        mainPanel = new JPanel(new BorderLayout());
        configPanel = new ConfigurationPanel(plugin.getGPTService());
        console = new Console();

        // Create tabbed pane
        tabbedPane = new JTabbedPane();

        // Configuration tab
        JPanel configTab = new JPanel(new BorderLayout());
        configTab.add(configPanel, BorderLayout.CENTER);
        JPanel buttonPanel = createButtonPanel();
        configTab.add(buttonPanel, BorderLayout.SOUTH);

        tabbedPane.addTab("Configuration", configTab);
        tabbedPane.addTab("Console", console);

        mainPanel.add(tabbedPane, BorderLayout.CENTER);

        setVisible(true);
        createActions();
    }

    /**
     * Shows the configuration panel and brings the provider to front
     */
    public void showConfigurationTab() {
        tabbedPane.setSelectedIndex(0); // Configuration tab
        toFront();
    }

    /**
     * Switches to the console tab to show results
     */
    private void switchToConsoleTab() {
        tabbedPane.setSelectedIndex(1); // Console tab
        toFront();
    }

    private JPanel createButtonPanel() {
        // Return empty panel - buttons removed from configuration page
        return new JPanel();
    }

    private void createActions() {
        // Main context menu actions for GPT analysis
        createRewriteAction();
        createExplainAction();
        createAuditAction();
    }

    private void createRewriteAction() {
        DockingAction rewriteAction = new DockingAction("Rewrite", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                rewriteFunctionFromContext(context);
            }

            @Override
            public boolean isEnabledForContext(ActionContext context) {
                return isValidFunctionContext(context);
            }
        };

        rewriteAction.setPopupMenuData(new MenuData(new String[] { "GhidraGPT", "Rewrite" }, null, "b"));
        rewriteAction.setDescription("Recover symbol names, variable types, the prototype, and comments for the selected function");

        plugin.getTool().addAction(rewriteAction);
    }

    private void createAuditAction() {
        DockingAction auditAction = new DockingAction("Audit", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                auditFunctionFromContext(context);
            }

            @Override
            public boolean isEnabledForContext(ActionContext context) {
                return isValidFunctionContext(context);
            }
        };

        auditAction.setPopupMenuData(new MenuData(new String[] { "GhidraGPT", "Audit" }, null, "c"));
        auditAction.setDescription("Review the selected function's decompiled code for likely security issues (single-function, not whole-program)");

        plugin.getTool().addAction(auditAction);
    }

    private void createExplainAction() {
        DockingAction explainAction = new DockingAction("Explain", getName()) {
            @Override
            public void actionPerformed(ActionContext context) {
                explainFunctionFromContext(context);
            }

            @Override
            public boolean isEnabledForContext(ActionContext context) {
                return isValidFunctionContext(context);
            }
        };

        explainAction.setPopupMenuData(new MenuData(new String[] { "GhidraGPT", "Explain" }, null, "a"));
        explainAction.setDescription("Explain the behavior of the selected function");

        plugin.getTool().addAction(explainAction);
    }

    private boolean isValidFunctionContext(ActionContext context) {
        // Handle decompiler context first (most specific)
        if (context instanceof DecompilerActionContext) {
            DecompilerActionContext decompilerContext = (DecompilerActionContext) context;
            return decompilerContext.getFunction() != null;
        }

        // Handle listing context
        if (context instanceof ListingActionContext) {
            ListingActionContext listingContext = (ListingActionContext) context;
            if (listingContext.getLocation() == null || listingContext.getProgram() == null) {
                return false;
            }

            // Get function at the current address
            Program program = listingContext.getProgram();
            Address address = listingContext.getAddress();
            Function function = program.getFunctionManager().getFunctionAt(address);
            if (function != null) {
                return true;
            }

            // Check if the address is contained within any function
            function = program.getFunctionManager().getFunctionContaining(address);
            return function != null;
        }

        // Handle general program context
        if (context instanceof ProgramActionContext) {
            ProgramActionContext programContext = (ProgramActionContext) context;
            if (programContext.getProgram() == null) {
                return false;
            }

            Program program = programContext.getProgram();
            // Try to get the function from the current tool context
            ActionContext toolContext = plugin.getTool().getActiveComponentProvider().getActionContext(null);
            if (toolContext instanceof ListingActionContext) {
                ListingActionContext listingContext = (ListingActionContext) toolContext;
                if (listingContext.getAddress() != null) {
                    Function function = program.getFunctionManager().getFunctionContaining(listingContext.getAddress());
                    return function != null;
                }
            }
        }

        return false;
    }

    private Function getFunctionFromContext(ActionContext context) {
        // Handle decompiler context first (most direct)
        if (context instanceof DecompilerActionContext) {
            DecompilerActionContext decompilerContext = (DecompilerActionContext) context;
            return decompilerContext.getFunction();
        }

        // Handle listing context
        if (context instanceof ListingActionContext) {
            ListingActionContext listingContext = (ListingActionContext) context;
            if (listingContext.getLocation() == null || listingContext.getProgram() == null) {
                return null;
            }

            Program program = listingContext.getProgram();
            Address address = listingContext.getAddress();

            // First try to get function at exact address
            Function function = program.getFunctionManager().getFunctionAt(address);
            if (function != null) {
                return function;
            }

            // If not found, try to get function containing the address
            return program.getFunctionManager().getFunctionContaining(address);
        }

        // Handle general program context
        if (context instanceof ProgramActionContext) {
            ProgramActionContext programContext = (ProgramActionContext) context;
            if (programContext.getProgram() == null) {
                return null;
            }

            Program program = programContext.getProgram();
            // Try to get the function from the current tool context
            ActionContext toolContext = plugin.getTool().getActiveComponentProvider().getActionContext(null);
            if (toolContext instanceof ListingActionContext) {
                ListingActionContext listingContext = (ListingActionContext) toolContext;
                if (listingContext.getAddress() != null) {
                    Address address = listingContext.getAddress();
                    Function function = program.getFunctionManager().getFunctionAt(address);
                    if (function != null) {
                        return function;
                    }
                    return program.getFunctionManager().getFunctionContaining(address);
                }
            }
        }

        return null;
    }

    private Program getProgramFromContext(ActionContext context) {
        // Handle decompiler context
        if (context instanceof DecompilerActionContext) {
            return ((DecompilerActionContext) context).getProgram();
        }

        // Handle listing context
        if (context instanceof ListingActionContext) {
            return ((ListingActionContext) context).getProgram();
        }

        // Handle general program context
        if (context instanceof ProgramActionContext) {
            return ((ProgramActionContext) context).getProgram();
        }

        return null;
    }

    private Function getCurrentFunction() {
        if (currentProgram == null)
            return null;

        // Get the current listing context to find the selected function
        ActionContext context = plugin.getTool().getActiveComponentProvider().getActionContext(null);
        if (context instanceof ListingActionContext) {
            return getFunctionFromContext(context);
        }

        return null;
    }

    private void rewriteFunction() {
        executeAnalysis("Rewriting function...",
                (function, monitor) -> gptService.rewriteFunction(function, currentProgram, monitor));
    }

    private void auditFunction() {
        executeAnalysis("Auditing function...",
                (function, monitor) -> gptService.auditFunction(function, currentProgram, monitor));
    }

    private void explainFunction() {
        executeAnalysis("Explaining function...",
                (function, monitor) -> gptService.explainFunction(function, currentProgram, monitor));
    }

    // Context-aware methods for context menu actions

    private void rewriteFunctionFromContext(ActionContext context) {
        Function function = getFunctionFromContext(context);
        Program program = getProgramFromContext(context);
        executeAnalysisWithContext("Rewriting function...", function, program,
                (f, p, monitor) -> gptService.rewriteFunction(f, p, monitor));
    }

    private void auditFunctionFromContext(ActionContext context) {
        Function function = getFunctionFromContext(context);
        Program program = getProgramFromContext(context);
        executeAnalysisWithContext("Auditing function...", function, program,
                (f, p, monitor) -> gptService.auditFunction(f, p, monitor));
    }

    private void explainFunctionFromContext(ActionContext context) {
        Function function = getFunctionFromContext(context);
        Program program = getProgramFromContext(context);
        executeAnalysisWithContext("Explaining function...", function, program,
                (f, p, monitor) -> gptService.explainFunction(f, p, monitor));
    }

    private void executeAnalysis(String taskName, AnalysisTask task) {
        Function function = getCurrentFunction();
        if (function == null) {
            Msg.showError(this, mainPanel, "Error", "No function selected");
            return;
        }

        if (!configPanel.isConfigured()) {
            Msg.showError(this, mainPanel, "Error", "Please configure API settings first");
            showConfigurationTab();
            return;
        }

        // Execute analysis in background thread without showing loading dialog
        Thread analysisThread = new Thread(() -> {
            // Create a simple no-op monitor since we rely on console streaming for progress
            TaskMonitor monitor = new TaskMonitorAdapter();

            try {
                // Switch to console tab to show streaming output
                SwingUtilities.invokeLater(() -> {
                    switchToConsoleTab();
                });

                String result = task.execute(function, monitor);

                // No need to log result - streaming console methods handle the display

            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> {
                    console.appendError(function.getName(), "Failed to analyze function: " + e.getMessage());
                });
            }
        });

        analysisThread.setName("GhidraGPT-" + taskName);
        analysisThread.start();
    }

    private void executeAnalysisWithContext(String taskName, Function function, Program program,
            AnalysisTaskWithContext task) {
        if (function == null) {
            Msg.showError(this, getComponent(), "Error", "No function selected");
            return;
        }

        if (!configPanel.isConfigured()) {
            Msg.showError(this, getComponent(), "Error", "Please configure API settings first");
            showConfigurationTab();
            return;
        }

        // Execute analysis in background thread without showing loading dialog
        Thread analysisThread = new Thread(() -> {
            // Create a simple no-op monitor since we rely on console streaming for progress
            TaskMonitor monitor = new TaskMonitorAdapter();

            try {
                // Switch to console tab to show streaming output
                SwingUtilities.invokeLater(() -> {
                    switchToConsoleTab();
                });

                String result = task.execute(function, program, monitor);

                // No need to log result - streaming console methods handle the display

            } catch (Exception e) {
                SwingUtilities.invokeLater(() -> {
                    console.appendError(function.getName(), "Failed to analyze function: " + e.getMessage());
                });
            }
        });

        analysisThread.setName("GhidraGPT-" + taskName);
        analysisThread.start();
    }

    @FunctionalInterface
    private interface AnalysisTask {
        String execute(Function function, TaskMonitor monitor) throws Exception;
    }

    @FunctionalInterface
    private interface AnalysisTaskWithContext {
        String execute(Function function, Program program, TaskMonitor monitor) throws Exception;
    }

    @Override
    public JComponent getComponent() {
        return mainPanel;
    }

    public void programActivated(Program program) {
        this.currentProgram = program;
        if (gptService != null) {
            gptService.dispose();
        }
        gptService = new GhidraGPTService(plugin.getGPTService(), console);
        gptService.initializeDecompiler(program);
    }

    public void programDeactivated(Program program) {
        if (gptService != null) {
            gptService.dispose();
            gptService = null;
        }
        this.currentProgram = null;
    }

    @Override
    public void componentHidden() {
        // Clean up when component is hidden
    }

    /**
     * Logs analysis results to our dedicated GhidraGPT console
     */
    private void logResultToConsole(String functionName, String analysisType, String result) {
        console.appendAnalysisResult(functionName, analysisType, result);
    }

    @Override
    public void componentShown() {
        // Refresh when component is shown
    }

    public void dispose() {
        if (gptService != null) {
            gptService.dispose();
            gptService = null;
        }
    }

}
