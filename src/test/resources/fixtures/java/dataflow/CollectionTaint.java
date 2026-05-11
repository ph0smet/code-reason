import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class CollectionTaint {

    static String source() {
        return System.getenv("USER_INPUT");
    }

    static void sink(String s) {
        System.out.println(s);
    }

    public void caseDirectAssignment() {
        String taint = source();
        String passed = taint;
        sink(passed);
    }

    public void caseArray() {
        String[] arr = new String[1];
        arr[0] = source();
        sink(arr[0]);
    }

    public void caseListAdd() {
        List<String> list = new ArrayList<>();
        list.add(source());
        sink(list.get(0));
    }

    public void caseMapPut() {
        Map<String, String> map = new HashMap<>();
        map.put("key", source());
        sink(map.get("key"));
    }
}
