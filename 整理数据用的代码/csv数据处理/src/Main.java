

public class Main {

    public static void main(String[] args) {
        MessData[] messData = new MessData[]{
                new Behavior("_behavior"),
                new OverView("_overview"),
                new NetWork("_network"),
                new Static("_static")
        };
        for (MessData md : messData) {
            md.deal();
        }
//        messData[3].dealDebug();
//        messData[3].deal();

    }

}
