import java.util.ArrayList;


class NetWork extends MessData {
    private final String[] domains = {
            "domain", "ip"
    };

    NetWork(String dataType) {
        super(dataType);
    }

    @Override
    public String deal(ArrayList<ArrayList<String>> blocks) {
        return
                createJsonObjectFromObject(new String[]{
                        createJsonKeyValue("hash", hash),
                        dealDomainIp(blocks.get(1)),
                        dealHost(blocks.get(2))

                });
    }

    private String dealDomainIp(ArrayList<String> muLine) {
        ArrayList<String> oa = new ArrayList<>();
        for (int i = 2; i < muLine.size(); i++) {
            String[] vs = muLine.get(i).split(",");
            oa.add(
                    createJsonObjectFromValue(vs, domains)
            );
        }
        return createJsonKeyObject(
                "domain",
                createJsonArrayFromObject(oa)
        );

    }

    private String dealHost(ArrayList<String> muLine) {
        if (muLine.size() < 3) {
            return createJsonKeyObject(
                    "host",
                    "[]"
            );
        } else {
            return createJsonKeyObject(
                    "host",
                    createJsonArrayFromValue(
                            joinMuLine(2, muLine, ",").split(",")
                    )
            );
        }
    }

}
