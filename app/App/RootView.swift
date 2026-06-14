import SwiftUI

struct RootView: View {
    @Environment(AppModel.self) private var model

    var body: some View {
        @Bindable var model = model
        NavigationSplitView {
            Sidebar()
                .navigationSplitViewColumnWidth(min: 300, ideal: 300, max: 300)
//                .toolbar(removing: .sidebarToggle)
        } detail: {
            SignScreen()
                .frame(minWidth: 720)
        }
        .navigationSplitViewStyle(.balanced)
        .tint(Brand.tint)
        .sheet(isPresented: $model.showSignIn) { SignInSheet() }
        .sheet(isPresented: $model.showActivity) { ActivitySheet() }
        .task { await model.refreshAccountOnLaunch() }
        .onAppear { model.startDeviceWatch() }
    }
}
