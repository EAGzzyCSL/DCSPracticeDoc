import java.util.ArrayList;

class Behavior extends MessData {


    Behavior(String dataType) {
        super(dataType);
    }

    @Override
    public String deal(ArrayList<ArrayList<String>> blocks) {
        // 前面的都忽略
        ArrayList<String> muLine = blocks.get(2);
        ArrayList<String> jsonArray = new ArrayList<>();
        String[] keys = {
                "name", "pid"
        };
        for (int i = 1; i < muLine.size(); i++) {
            String[] kv = muLine.get(i).split(",");
            jsonArray.add(createJsonObjectFromValue(kv, keys));
        }
        return createJsonObjectFromObject(new String[]{
                createJsonKeyValue("hash", hash),
                createJsonKeyObject("behavior",
                        createJsonArrayFromObject(jsonArray)
                )
        });
    }

}
