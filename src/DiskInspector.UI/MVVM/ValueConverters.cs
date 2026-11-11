using System.Globalization;
using System.Windows;
using System.Windows.Data;
using System.Windows.Media;
using DiskInspector.Core.Enums;

namespace DiskInspector.UI.MVVM;

public sealed class RiskToForegroundBrushConverter : IValueConverter
{
    private static readonly SolidColorBrush GreenBrush = CreateFrozen(0x4A, 0xDE, 0x80);
    private static readonly SolidColorBrush YellowBrush = CreateFrozen(0xFA, 0xCC, 0x15);
    private static readonly SolidColorBrush RedBrush = CreateFrozen(0xF8, 0x71, 0x71);
    private static readonly SolidColorBrush GrayBrush = CreateFrozen(0x94, 0xA3, 0xB8);

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is RiskLevel risk)
        {
            return risk switch
            {
                RiskLevel.Green => GreenBrush,
                RiskLevel.Yellow => YellowBrush,
                RiskLevel.Red => RedBrush,
                RiskLevel.Gray => GrayBrush,
                _ => GrayBrush
            };
        }

        return GrayBrush;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        Binding.DoNothing;

    private static SolidColorBrush CreateFrozen(byte r, byte g, byte b)
    {
        SolidColorBrush brush = new(Color.FromRgb(r, g, b));
        brush.Freeze();
        return brush;
    }
}

public sealed class RiskToBackgroundBrushConverter : IValueConverter
{
    private static readonly SolidColorBrush GreenBg = CreateFrozen(0x28, 0x22, 0xC5, 0x5E);
    private static readonly SolidColorBrush YellowBg = CreateFrozen(0x28, 0xEA, 0xB3, 0x08);
    private static readonly SolidColorBrush RedBg = CreateFrozen(0x28, 0xEF, 0x44, 0x44);
    private static readonly SolidColorBrush GrayBg = CreateFrozen(0x30, 0x64, 0x74, 0x8B);

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is RiskLevel risk)
        {
            return risk switch
            {
                RiskLevel.Green => GreenBg,
                RiskLevel.Yellow => YellowBg,
                RiskLevel.Red => RedBg,
                RiskLevel.Gray => GrayBg,
                _ => GrayBg
            };
        }

        return GrayBg;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        Binding.DoNothing;

    private static SolidColorBrush CreateFrozen(byte a, byte r, byte g, byte b)
    {
        SolidColorBrush brush = new(Color.FromArgb(a, r, g, b));
        brush.Freeze();
        return brush;
    }
}

public sealed class HexToBrushConverter : IValueConverter
{
    private static readonly BrushConverter Converter = new();

    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        if (value is string hex && !string.IsNullOrWhiteSpace(hex))
        {
            try
            {
                if (Converter.ConvertFromString(hex) is SolidColorBrush brush)
                {
                    if (brush.CanFreeze)
                    {
                        brush.Freeze();
                    }
                    return brush;
                }
            }
            catch
            {
                // Fallback abaixo
            }
        }

        return Brushes.DodgerBlue;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        Binding.DoNothing;
}

public sealed class BoolToVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        bool flag = value is bool b && b;
        if (parameter is string s && s.Equals("Inverse", StringComparison.OrdinalIgnoreCase))
        {
            flag = !flag;
        }

        return flag ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        value is Visibility v && v == Visibility.Visible;
}

public sealed class NullOrEmptyToVisibilityConverter : IValueConverter
{
    public object Convert(object? value, Type targetType, object? parameter, CultureInfo culture)
    {
        bool hasContent = value switch
        {
            null => false,
            string str => !string.IsNullOrWhiteSpace(str),
            _ => true
        };

        if (parameter is string s && s.Equals("Inverse", StringComparison.OrdinalIgnoreCase))
        {
            hasContent = !hasContent;
        }

        return hasContent ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object? value, Type targetType, object? parameter, CultureInfo culture) =>
        Binding.DoNothing;
}

