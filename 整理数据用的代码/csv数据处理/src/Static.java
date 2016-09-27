import java.util.ArrayList;

public class Static extends MessData {

    private final String[] sections = {
            "Name", "Virtual_Address", "Virtual_Size", "Size_of_Raw_Data", "Entropy"
    };
    private final String[] resources = {
            "Name", "Offset", "Size", "Language", "Sub-language", "File type"
    };

    Static(String dataType) {
        super(dataType);
    }

    @Override
    public String deal(ArrayList<ArrayList<String>> blocks) {
        if (blocks.size() == 7) {
            // 没有resources这一段
            return
                    createJsonObjectFromObject(new String[]{
                            createJsonKeyValue("hash", hash),
                            dealPEimphash(blocks.get(1)),
                            dealSections(blocks.get(3)),
                            "\"resources\":[]",
                            dealImports(blocks.get(4)),
                            dealAntivirus(blocks.get(6))
                    });
        } else if (blocks.size() == 8) {
            return
                    createJsonObjectFromObject(new String[]{
                            createJsonKeyValue("hash", hash),
                            dealPEimphash(blocks.get(1)),
                            dealSections(blocks.get(3)),
                            dealResources(blocks.get(4)),
                            dealImports(blocks.get(5)),
                            dealAntivirus(blocks.get(7))
                    });
        }
        return null;
    }

    private String dealResources(ArrayList<String> muLines) {
        ArrayList<String> jsonObject = new ArrayList<>();
        for (int i = 2; i < muLines.size(); i++) {
            String[] vs = muLines.get(i).split(",", 6);
            jsonObject.add(
                    createJsonObjectFromValue(
                            vs, resources
                    )
            );
        }
        return createJsonKeyObject(
                "resources",
                createJsonArrayFromObject(jsonObject)
        );

    }

    private String dealPEimphash(ArrayList<String> muLines) {
        if (muLines.size() > 3) {
            String dllName = muLines.get(2);
            createJsonKeyValue(
                    "dllName",
                    dllName.substring(0, dllName.length() - 1)
            );
            ArrayList<String> dllInfos = new ArrayList<>();
            for (int i = 3; i < muLines.size() - 1; i++) {
                String tmp = muLines.get(i);
                dllInfos.add(tmp.substring(2, tmp.length()));
            }
            return createJsonKeyObject(
                    "PEimphash",
                    createJsonArrayFromValue(dllInfos)
            );
        } else {
            ArrayList<String> dllInfos = new ArrayList<>();
            for (int i = 1; i < muLines.size(); i++) {
                dllInfos.add(muLines.get(i));
            }
            return createJsonKeyObject(
                    "PEimphash",
                    createJsonArrayFromValue(dllInfos)
            );
        }
    }

    private String dealSections(ArrayList<String> muLines) {
        ArrayList<String> jsonObject = new ArrayList<>();
        for (int i = 2; i < muLines.size(); i++) {
            String[] vs = muLines.get(i).split(",");
            jsonObject.add(
                    createJsonObjectFromValue(vs, sections)
            );
        }
        return createJsonKeyObject(
                "sections",
                createJsonArrayFromObject(jsonObject)
        );
    }

    private String dealImports(ArrayList<String> muLines) {
        ArrayList<String> vs = new ArrayList<>();
        for (int i = 1; i < muLines.size(); i++) {
            String[] tmp = muLines.get(i).split(",", 2);
            if (tmp.length < 2) {
                System.out.println(muLines.get(i));
            }
            vs.add(
                    createJsonKeyValue(tmp[0], tmp[1])
            );
        }
        return createJsonKeyObject("imports",
                createJsonObjectFromObject(vs)
        );
    }

    private String dealAntivirus(ArrayList<String> muLines) {
        ArrayList<String> kvs = new ArrayList<>();
        for (int i = 2; i < muLines.size(); i++) {
            String[] kv = muLines.get(i).split(",");
            kvs.add(
                    createJsonKeyValue(kv[0], kv[1])
            );
        }
        String[] aaa = new String[kvs.size()];
        kvs.toArray(aaa);
        return createJsonKeyObject(
                "antivirus",
                createJsonObjectFromObject(aaa)
        );
    }
}
