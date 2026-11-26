public class AnalysisResults {
    static String input() { return "user"; }
    static void sink(String value) { System.out.println(value); }

    void independent() {
        String user = input();
        String safe = "constant";
        sink(safe);
        UnknownApi.consume(user);
    }

    void isolated() {
        String detached = input();
    }
}
