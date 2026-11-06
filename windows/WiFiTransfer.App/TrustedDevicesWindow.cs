using System.Windows;
using System.Windows.Controls;
using WiFiTransfer.App.Services;

namespace WiFiTransfer.App;

public sealed class TrustedDevicesWindow : Window
{
    private readonly TrustedDeviceStore _store;
    private readonly ListBox _devices = new();

    public TrustedDevicesWindow(TrustedDeviceStore store)
    {
        _store = store;
        Title = "Manage paired Android devices";
        Width = 620;
        Height = 390;
        MinWidth = 500;
        MinHeight = 300;
        WindowStartupLocation = WindowStartupLocation.CenterOwner;
        Background = System.Windows.Media.Brushes.White;

        var root = new Grid { Margin = new Thickness(18) };
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });
        root.RowDefinitions.Add(new RowDefinition { Height = new GridLength(1, GridUnitType.Star) });
        root.RowDefinitions.Add(new RowDefinition { Height = GridLength.Auto });

        var heading = new TextBlock
        {
            Text = "Trusted devices",
            FontSize = 20,
            FontWeight = FontWeights.SemiBold,
            Margin = new Thickness(0, 0, 0, 12)
        };
        Grid.SetRow(heading, 0);
        root.Children.Add(heading);

        _devices.DisplayMemberPath = nameof(TrustedDevice.DisplayLabel);
        _devices.Margin = new Thickness(0, 0, 0, 12);
        Grid.SetRow(_devices, 1);
        root.Children.Add(_devices);

        var buttons = new StackPanel
        {
            Orientation = Orientation.Horizontal,
            HorizontalAlignment = HorizontalAlignment.Right
        };
        var revoke = new Button { Content = "Revoke selected device", Padding = new Thickness(14, 8, 14, 8), Margin = new Thickness(0, 0, 8, 0) };
        revoke.Click += RevokeSelected_Click;
        var close = new Button { Content = "Close", Padding = new Thickness(14, 8, 14, 8), IsCancel = true };
        close.Click += (_, _) => Close();
        buttons.Children.Add(revoke);
        buttons.Children.Add(close);
        Grid.SetRow(buttons, 2);
        root.Children.Add(buttons);

        Content = root;
        RefreshDevices();
    }

    private void RefreshDevices()
    {
        _devices.ItemsSource = _store.GetAll().Where(d => !d.IsRevoked).ToList();
    }

    private void RevokeSelected_Click(object sender, RoutedEventArgs e)
    {
        if (_devices.SelectedItem is not TrustedDevice selected)
        {
            MessageBox.Show(this, "Select a paired device first.", "DroidShare-WiFi",
                MessageBoxButton.OK, MessageBoxImage.Information);
            return;
        }

        var confirm = MessageBox.Show(this,
            "Revoke " + selected.DeviceName + "? This device will no longer be trusted by this Windows installation.",
            "Revoke paired device", MessageBoxButton.YesNo, MessageBoxImage.Warning, MessageBoxResult.No);
        if (confirm != MessageBoxResult.Yes) return;

        _store.Revoke(selected.DeviceId);
        RefreshDevices();
    }
}
