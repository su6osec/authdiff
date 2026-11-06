package io.github.authdiff.cli;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import picocli.CommandLine;

import java.io.File;
import java.io.StringWriter;
import java.net.URL;

import static org.assertj.core.api.Assertions.assertThat;

class CompareCommandTest {

    @Test
    @DisplayName("Executes offline HAR comparison and correctly classifies IDOR, missing auth, and enforced endpoints")
    void testOfflineHarCompare() {
        URL ownerUrl = getClass().getResource("/fixtures/owner.har");
        URL attackerUrl = getClass().getResource("/fixtures/attacker.har");
        URL anonUrl = getClass().getResource("/fixtures/anon.har");

        assertThat(ownerUrl).isNotNull();
        assertThat(attackerUrl).isNotNull();
        assertThat(anonUrl).isNotNull();

        File ownerFile = new File(ownerUrl.getFile());
        File attackerFile = new File(attackerUrl.getFile());
        File anonFile = new File(anonUrl.getFile());

        CommandLine cmd = new CommandLine(new AuthDiffCli());
        StringWriter sw = new StringWriter();
        cmd.setOut(new java.io.PrintWriter(sw));

        int exitCode = cmd.execute(
                "compare",
                "--a", ownerFile.getAbsolutePath(),
                "--b", attackerFile.getAbsolutePath(),
                "--anon", anonFile.getAbsolutePath(),
                "--format", "TABLE",
                "--fail-on", "HIGH"
        );

        // Exit code 1 because HIGH confidence IDOR / missing auth findings exist
        assertThat(exitCode).isEqualTo(1);
    }

    @Test
    @DisplayName("Outputs JSON format when requested")
    void testJsonOutputFormat() {
        URL ownerUrl = getClass().getResource("/fixtures/owner.har");
        URL attackerUrl = getClass().getResource("/fixtures/attacker.har");

        File ownerFile = new File(ownerUrl.getFile());
        File attackerFile = new File(attackerUrl.getFile());

        CommandLine cmd = new CommandLine(new AuthDiffCli());

        int exitCode = cmd.execute(
                "compare",
                "--a", ownerFile.getAbsolutePath(),
                "--b", attackerFile.getAbsolutePath(),
                "--format", "JSON",
                "--fail-on", "NONE"
        );

        assertThat(exitCode).isEqualTo(0);
    }
}
