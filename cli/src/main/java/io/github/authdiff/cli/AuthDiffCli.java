package io.github.authdiff.cli;

import picocli.CommandLine;
import picocli.CommandLine.Command;

/**
 * Main command-line entrypoint for authdiff.
 */
@Command(
        name = "authdiff",
        mixinStandardHelpOptions = true,
        version = "authdiff 0.1.0",
        description = "Authorization diffing tool for finding IDOR/BOLA and broken authentication.",
        subcommands = {
                CompareCommand.class,
                ReplayCommand.class
        }
)
public final class AuthDiffCli implements Runnable {

    private static final String BANNER = """
            ================================================================================
               authdiff - Broken Access Control & IDOR/BOLA Detection Engine
            ================================================================================
            LEGAL NOTICE:
            authdiff is designed strictly for authorized penetration testing, security audits,
            and research on systems you own or have explicit, documented permission to test.
            Unauthorized scanning, replaying, or accessing systems without permission is illegal.
            ================================================================================
            """;

    @Override
    public void run() {
        System.out.println(BANNER);
        System.out.println("Use 'authdiff --help' or 'authdiff [command] --help' for usage instructions.");
    }

    public static void main(String[] args) {
        CommandLine cmd = new CommandLine(new AuthDiffCli());
        cmd.setExecutionExceptionHandler((ex, commandLine, parseResult) -> {
            System.err.println("[!] Error: " + ex.getMessage());
            return 2;
        });

        int exitCode = cmd.execute(args);
        System.exit(exitCode);
    }
}
